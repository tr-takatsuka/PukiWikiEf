<?php

class EncryptFile
{
	const SESSIONNAME_PASSWORD = 'encryptfile_password';
	
	private static function encryptCore( $fGetSrc, $sizeSrc, $fPutDst, $password )
	{
		if( !$password ) return false;
		$method = 'bf-cbc';	// 'AES-128-CBC';
		$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
		$blockSize = strlen($iv);
		$dst = "\0". $method . "\0" . $sizeSrc . "\0" . $iv;					// 暗号化ファイルのヘッダ
		$fPutDst($dst);
		while( !@$last ){
			$src = $fGetSrc($blockSize);
			$last = strlen($src)==0 || ( strlen($src) % $blockSize ) > 0;		// 最後？
			$options = OPENSSL_RAW_DATA;
			if( !$last ) $options |= OPENSSL_ZERO_PADDING;
			$dst = openssl_encrypt( $src, $method, $password, $options, $iv );
			if( $dst === false ) return false;
			$fPutDst($dst);
			$iv = substr( $dst, 0-$blockSize );
		}
		return true;
	}

	// ファイルを暗号化する
	public static function encryptFileUser( $pathSrc, $pathDst )
	{
		set_time_limit( 60 * 60 * 12 );			// 12時間

		$fpSrc = null;
		$fpDst = null;
		$bSucceeded = call_user_func( function()use($pathSrc,$pathDst,&$fpSrc,&$fpDst)
		{
			if( ($pw=@$_SESSION[self::SESSIONNAME_PASSWORD]) === null ){
				return false;
			}
			if( ($fpSrc=@fopen($pathSrc,'rb'))===false || !flock($fpSrc,LOCK_SH) ){
				return false;
			}
			{// 暗号化済ファイルをさらに暗号化することは不可
				$t = fread($fpSrc, 64);
				rewind($fpSrc);
				if( self::checkDecrypt($t) !== false ){		// 暗号化済？
					return false;
				}
			}
			$fileSize = filesize($pathSrc);
			if( ($fpDst=@fopen($pathDst,'w+b'))===false || !flock($fpDst,LOCK_EX) ){			// verify するので 'w+b'
				return false;
			}
			$fGetSrc = function($blockSize)use(&$fpSrc)
				{
					if( feof($fpSrc) ) return '';
					$data = fread( $fpSrc, $blockSize*1024*1024 );
					return $data;
				};
			$fPutDst = function($data)use(&$fpDst)
				{
					fwrite( $fpDst, $data );
				};
			if( !self::encryptCore( $fGetSrc, $fileSize, $fPutDst, $pw ) ){
				return false;
			}
			
			{// verify処理
				if( !rewind($fpSrc) || !rewind($fpDst) ) return false;
				if( ( $info = self::checkDecrypt(fread($fpDst,64)) ) === false ) return false;
				if( fseek($fpDst,$info->offset)!==0 ) return false;
				$fGetSrc = function($blockSize)use(&$fpDst)
					{
						$src->data = fread( $fpDst, $blockSize*1024*1024 );
						$src->isLast = feof($fpDst);
						return $src;
					};
				$fPutDst = function($dst)use(&$fpSrc)
					{
						return $dst === fread($fpSrc,strlen($dst));
					};
				if( !self::decryptCore( $info, $fGetSrc, $fPutDst, $pw ) ){
					return false;
				}
			}

			return true;
		});
		@flock($fpDst,LOCK_UN);
		@fclose($fpDst);
		@flock($fpSrc,LOCK_UN);
		@fclose($fpSrc);
		return $bSucceeded;
	}

	public static function encryptData($data,$password)
	{
		$result = false;
		$fGetSrc = function($blockSize)use(&$data)
			{
				$t = $data;
				$data = '';
				return $t;
			};
		$fPutDst = function($dst)use(&$result)
			{
				@$result .= $dst;
			};
		$bSucceeded = self::encryptCore( $fGetSrc, strlen($data), $fPutDst, $password );
		return $bSucceeded ? $result : false;
	}

	public static function encryptDataUser($data)
	{
		if( ($pw=@$_SESSION[self::SESSIONNAME_PASSWORD]) === null ){
			return false;
		}
		return self::encryptData($data,$pw);
	}

	public static function encryptConvertFileUser( $path )
	{
		$tmpPath = tempnam( pathinfo($path)['dirname'], 'ef_' );
		$bSucceeded = false;
		if( false !== self::encryptFileUser( $path, $tmpPath ) ){
			if( false !== rename( $tmpPath, $path ) ){
				$bSucceeded = true;
			}
		}
		unlink($tmpPath);
		return $bSucceeded;
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

	private static function decryptCore( $decInfo, $fGetSrc, $fPutDst, $password )
	{
		$iv = $decInfo->iv;
		do{
			$src = $fGetSrc( strlen($decInfo->iv) );
			$options = OPENSSL_RAW_DATA;
			if( !$src->isLast ) $options |= OPENSSL_ZERO_PADDING;
			if( ($dst=openssl_decrypt( $src->data, $decInfo->method, $password, $options, $iv )) === false ){
				return false;	// error! decrypt.;
			}
			$iv = substr( $src->data, 0-strlen($decInfo->iv) );
			if( !$fPutDst($dst) ) return false;	// error! decrypt.;
		}while( !$src->isLast );
		return true;
	}

	// 復号する
	// ・暗号化されてれば復号して返す。暗号化されてなければ引数をそのまま返す。
	// ・復号が失敗した場合は、false が返る。
	public static function decryptData($data,$password)
	{
		if( ($info=self::checkDecrypt($data)) === false ){
			return $data;
		}
		$data = substr( $data, $info->offset );
		$result = false;
		$fGetSrc = function($blockSize)use(&$data)
			{
				$src->data = $data;
				$src->isLast = true;
				return $src;
			};
		$fPutDst = function($dst)use(&$result)
			{
				$result .= $dst;
				return true;
			};
		if( !self::decryptCore( $info, $fGetSrc, $fPutDst, $password ) ){
			return false;
		}
		return $result;
	}

	public static function decryptDataUser($data)
	{
		return self::decryptData( $data, @$_SESSION[self::SESSIONNAME_PASSWORD] );
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
		$result->encryptedMethod = false;
		$data = fread($fp, 64);
		fclose($fp);
		if( ( $info = self::checkDecrypt($data) ) !== false ){		// 暗号化済？
			$result->size = $info->size;
			$result->encryptedMethod = $info->method;
		}
		return $result;
	}

	public static function downloadFileUser( $path )
	{
		set_time_limit( 60 * 60 * 12 );			// 12時間

		$fp = null;
		$bSucceeded = call_user_func( function()use($path,&$fp)
		{
			if( ($pw=@$_SESSION[self::SESSIONNAME_PASSWORD]) === null ){
				return false;
			}

			if( ($fp=@fopen($path, 'rb'))===false || !flock($fp,LOCK_SH) ){
				return false;
			}
			$data = fread($fp, 64);
			if( ( $info = self::checkDecrypt($data) ) !== false ){		// 暗号化済？
				fseek($fp,$info->offset);

				// 出力バッファレベルを0に変更
				while( ob_get_level() > 0 ) ob_end_flush();
				ob_start();

				$fGetSrc = function($blockSize)use(&$fp)
					{
						$src->data = fread( $fp, $blockSize*1024*1024 );
						$src->isLast = feof($fp);
						return $src;
					};
				$fPutDst = function($dst)
					{
						echo $dst;
						ob_flush();
						return true;
					};
				if( !self::decryptCore( $info, $fGetSrc, $fPutDst, $pw ) ){
					return false;
				}
			}else{
				@readfile($path);
			}
			return true;
		});
		@flock($fp,LOCK_UN);
		@fclose($fp);
		return $bSucceeded;
	}
}

