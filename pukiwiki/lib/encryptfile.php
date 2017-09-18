<?php

class EncryptFile
{

	private static function encryptFirst($password,$totalSize)
	{
		$ei->method = 'bf-cbc';
		$ei->password = $password;
		$ei->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($ei->method));
		$ei->data = "\0". $ei->method . "\0" . $totalSize . "\0" . $ei->iv;
		return $ei;
	}

	private static function encryptNext($ei,$data)
	{
		$ei->data = openssl_encrypt(
							$data,
							$ei->method,
							$ei->password,
							OPENSSL_RAW_DATA, 
							$ei->iv
						);
		if( $ei->data === false ) return false;
		$ei->iv = substr( $ei->data, 0-strlen($ei->iv) );
		return $ei;
	}

	// 暗号化する
	// ・失敗した場合は、false が返る。
	public static function encrypt($data,$password)
	{
		if( ( $ei = EncryptFile::encryptFirst($password,strlen($data)) ) === false ) return false;
		$result = $ei->data;
		if( ( $ei = EncryptFile::encryptNext($ei,$data) ) === false ) return false;
		return $result . $ei->data;
	}

	public static function encryptUser($data)
	{
		if( ( $pw = @$_SESSION['encryptfile_password'] ) === false ){
			return false;
		}
		return EncryptFile::encrypt($data,$pw);
	}

	private static function checkDecrypt($data)
	{
		$methods = implode('|',openssl_get_cipher_methods(true));
		if( preg_match( "/^\\0({$methods})\\0(\\d+)\\0/", $data, $matches ) ){		// 暗号化されてる？
			$result->method = $matches[1];
			$result->size = $matches[2];
			$ivLength = openssl_cipher_iv_length( $result->method );
			$result->iv = substr( $data, strlen($matches[0]), $ivLength  );
			$result->offset = strlen($matches[0]) + $ivLength;
			return $result;
		}
		return false;
	}

	// 復号する
	// ・暗号化されてれば復号して返す。暗号化されてなければ引数をそのまま返す。
	// ・復号が失敗した場合は、false が返る。
	public static function decrypt($data,$password)
	{
		$info = EncryptFile::checkDecrypt($data);
		if( $info === false ){
			return $data;
		}
		$data = openssl_decrypt(
						substr( $data, $info->offset ),
						$info->method,
						$password,
						OPENSSL_RAW_DATA,
						$info->iv );
		if( $data === false ){
			return false;	// error! decrypt.;
		}
		return $data;
	}

	public static function decryptUser($data)
	{
		$password = @$_SESSION['encryptfile_password'];
		$result = EncryptFile::decrypt($data,$password);
		return $result;
	}

	// 文字列から行毎の配列で取得
	// ・改行コードは消されずに残る
	public static function dataToLines($data)
	{
		$r = str_replace("\r", '', $data);
		$r = explode("\n",$r);
		$last = array_pop($r);
		$r = preg_replace("/$/", "\n", $r );
		if( strlen($last) > 0 ){
			array_push($r,$last);
		}
		return $r;
	}

	// 閲覧制限付きページ？
	public static function checkPageAuth($page)
	{
		global $auth_method_type,$read_auth_pages;
		// Checked by:
		$target_str = '';
		if ($auth_method_type == 'pagename') {
			$target_str = $page; // Page name
		} else if ($auth_method_type == 'contents') {
			$target_str = join('', get_source($page)); // Its contents
		}

		$user_list = array();
		foreach($read_auth_pages as $key=>$val)
			if (preg_match($key, $target_str))
				$user_list = array_merge($user_list, explode(',', $val));

		if (empty($user_list)) return false; // No limit

		return true;
	}

	public static function getFileInfo( $path )
	{
		$fp = @fopen($path, 'rb');
		if( $fp === false ) return false;
		$result->size = filesize($path);
		$result->isEncrypted = false;
		$data = fread($fp, 64);
		fclose($fp);
		if( ( $info = EncryptFile::checkDecrypt($data) ) !== false ){		// 暗号化済？
			$result->size = $info->size;
			$result->isEncrypted = true;
		}
		return $result;
	}

	public static function downloadFileUser( $path )
	{
		set_time_limit( 60 * 60 * 12 );			// 12時間

		$password = @$_SESSION['encryptfile_password'];

		$fp = @fopen($path, 'rb');
		if( $fp === false ) return false;
		$data = fread($fp, 64);
		if( ( $info = EncryptFile::checkDecrypt($data) ) !== false ){		// 暗号化済？
			fseek($fp,$info->offset);

			// 出力バッファレベルを0に変更
			while( ob_get_level() > 0 ) ob_end_clean();
 			ob_start();

			while( !feof($fp) ){
				$data = fread( $fp, strlen($info->iv)*1024*1024);
				$dec = openssl_decrypt(
					$data,
					$info->method,
					$password,
					OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
					$info->iv );
				if( $dec === false ){
					return false;	// error! decrypt.;
				}
				echo $dec;
				ob_flush();
				$info->iv = substr( $data, 0-strlen($info->iv) );
			}
			fclose($fp);

		}else{
			@readfile($this->filename);
		}
		return true;
	}

	public static function fileToEncrypt( $path )
	{
		set_time_limit( 60 * 60 * 12 );			// 12時間

		$password = @$_SESSION['encryptfile_password'];

		$fp = @fopen($path, 'rb');
		if( $fp === false ) return false;
		$data = fread($fp, 64);
		if( EncryptFile::checkDecrypt($data) !== false ){		// 暗号化済？
			fclose($fp);
			return true;
		}
		rewind($fp);
		$fileSize = filesize($path);
		
		$tmpPath = tempnam( pathinfo( $path )['dirname'], 'ef_' );		
		$tp = @fopen($tmpPath, 'wb');
		if( $tp === false ){
			fclose($fp);
			return false;
		}

		$ei = EncryptFile::encryptFirst($password,$fileSize);
		fwrite($tp, $ei->data );
		while( !feof($fp) ){
			$data = fread( $fp, strlen($ei->iv)*1024*1024 );
			$ei = EncryptFile::encryptNext($ei,$data);
			fwrite( $tp, $ei->data );
		}
		fclose($tp);
		fclose($fp);

		if( false === rename( $tmpPath, $path ) ){
			unlink($tmpPath);
			return false;
		}
		return true;

	}
	
}

