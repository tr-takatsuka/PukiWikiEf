<?php

// 参照を許可するフォルダ
const PLUGIN_REFSERVERFILES_FOLDERS = array(
	'./filelib/',
);

class Render
{
    // ファイル名を指定してレンダリングします
    public static function File($templateFile,$params,$escape=false)
    {
        if( $escape ){
            $funcEscape = function( $funcEscape, $val )
            {
                if( is_string($val) ){
                    $val = htmlentities($val,ENT_QUOTES);
                }elseif( is_array($val) ){
                    foreach( $val as $key => &$v ){
                        $v = $funcEscape($funcEscape,$v);
                    }
                }
                return $val;
            };
            $params = $funcEscape( $funcEscape, $params );
        }

        ob_start();
        extract($params);
        include $templateFile;
        $result = ob_get_contents();
        ob_end_clean();
        return $result;
    }

    // 文字列を渡してレンダリングします
    public static function String($string,$params,$escape=false)
    {
        $filepath = tmpfile();
        fwrite($filepath,$string);
        $metaData = stream_get_meta_data($filepath);
        $result = self::File($metaData['uri'],$params,$escape);
        return $result;
    }

}

class RefServerFiles
{
	public static function GetAccessablePath($path)
	{
		if( ( $pathReal = realpath($path) ) === false ){
			return false;
		}
		if( is_dir($pathReal) ){
			$pathReal = rtrim($pathReal, '/') . '/';
		}
		foreach( PLUGIN_REFSERVERFILES_FOLDERS as $f ){
			$p = realpath($f);
			if( is_file($p) ){
				if( $p == $pathReal ){
					return $pathReal;
				}
			}elseif( is_dir($p) ){
				$p = rtrim($p, '/') . '/';
				if( $p == substr($pathReal,0,strlen($p)) ){
					return $pathReal;
				}
			}
		}
		return false;
	}
	
	
}


require_once(PLUGIN_DIR.'attach.inc.php');		// attachプラグインのmime typeの処理を流用


function plugin_refserverfiles_convert()
{
	global $script,$vars,$digest;
	$args = func_get_args();
	if (count($args) == 0) {
		return 'refserverfiles() : Bad parameters;';
	}
	$argPath = array_shift($args);
	$argEnableSubFolder = array_shift($args);

	static $pluginNo = 0;
	$pluginNo++;
		
	if( ( $pathReal = RefServerFiles::GetAccessablePath($argPath) ) === false ){
		return "refserverfiles() : access denied \"{$argPath}\"";
	}

	if( is_file($pathReal) ){
		return "refserverfiles() : is file \"{$argPath}\"";
	}else if( is_dir($pathReal) ){
		$files = call_user_func( function()use($pathReal,$argEnableSubFolder)
			{
				$files = array();
				$queue[] = $pathReal;
				while( count($queue)>0 ){
					$dir = array_shift($queue);
					$dir = rtrim($dir,'/') . '/';
					$scanned = scandir($dir,SCANDIR_SORT_ASCENDING);
					foreach( $scanned as $f ){
						$fullPath = $dir . $f;
						if( $f == '.' || $f == '..' ){
						}elseif( is_file($fullPath) ){
							unset($fileInfo);
							$fileInfo->dispPath = substr($fullPath,0-(strlen($fullPath)-strlen($pathReal)));
							$fi = EncryptFile::getFileInfo($fullPath);
							$fileInfo->size = $fi->size;
							$fileInfo->encryptedMethod = $fi->encryptedMethod;
							$files[$fullPath] = $fileInfo;
						}elseif( is_dir($fullPath) && $argEnableSubFolder ){
							$queue[] = $fullPath;
						}
					}
				}
				return $files;
			});

		$_script = PKWK_READONLY ? '' : $script;;
		$_submit = PKWK_READONLY ? 'hidden' : 'submit';
		$_script_uri = get_script_uri();
		$_page = htmlsc( ( $u = @$vars['page'] ) ? : '' );
		$_digest = htmlsc($digest);

		$template = <<< EOD
<?php
	\$fUrlEnc = function(\$s)
		{
			return rawurlencode(\$s);
		};
	\$fToUtf8 = function(\$s)
		{
			return mb_convert_encoding( \$s, 'UTF-8', 'auto' );
		};
?>
<script type="text/javascript">
<!--
	function refserverfiles_toEncrypt_{$pluginNo}( path, dispPath )
	{
		if( window.confirm("do encrypt \"" + dispPath + "\" ?" )){
			document.refserverfiles_form_{$pluginNo}.path.value = path;
			return true;
		}else{
			return false;
		}
	}
// -->
</script>
<form name="refserverfiles_form_{$pluginNo}" action="{$_script}" method="post">
	<input type="hidden" name="plugin" value="refserverfiles" />
	<input type="hidden" name="refer" value="$_page" />
	<input type="hidden" name="digest" value="$_digest" />
	<input type="hidden" name="action" value="toencrypt" />
	<input type="hidden" name="path" value="" />
	<table class="style_calendar" cellspacing="1" border="0">
		<thead>
			<th>filename</th>
			<th>file size</th>
			<th>encrypt</th>
		</thead>
		<tbody>
			<?php foreach(\$files as \$fullPath => \$info ){ ?>
				<tr class="style_tr">
					<td class="style_td" style="text-align:left">
						<?php echo \$bEncryptable ?
							"<a href=\"{$_script_uri}?plugin=refserverfiles&amp;path={\$fUrlEnc(\$fullPath)}&amp;action=download\">{\$fToUtf8(\$info->dispPath)}</a>"
							: "{\$fToUtf8(\$info->dispPath)}";
						?>
					</td>
					<td class="style_td" style="text-align:right">
						<?php echo \$info->size; ?>
					</td>
					<td class="style_td" style="text-align:left">
						<?php
							if( \$info->encryptedMethod ){
								echo \$info->encryptedMethod;
							}else{
								echo \$info->encryptedMethod ? :
									( \$bEncryptable ? "<input type=\"{$_submit}\" value=\"To Encrypt\" class=\"submit\" onclick=\"refserverfiles_toEncrypt_{$pluginNo}('{\$fullPath}','{\$fToUtf8(\$info->dispPath)}')\" />" : '' );
							}
						?>
					</td>
				</tr>
			<?php } ?>
		</tbody>
	</table>
</form>
EOD;

		$params['files'] = $files;
		$params['bEncryptable'] = @$_SESSION[EncryptFile::SESSIONNAME_PASSWORD]!==null;
		return Render::String( $template, $params, false );
	}
	return '&amp;refserverfiles : unknown error.';
}

function plugin_refserverfiles_action()
{
	global	$vars;

	if( ($argPath=@$vars['path'])===null || ($argAction=@$vars['action'])===null ){
		return array('msg'=>"refserverfiles : bad parameters");
	}
	if( ($pathReal=RefServerFiles::GetAccessablePath($argPath))===false || !is_file($pathReal) ){
		return array('msg'=>"refserverfiles : access denied \"{$argPath}\"");
	}
	$filename = pathinfo( $pathReal )['basename'];

	switch( $argAction ){
	case 'download':
	
		$filename = mb_convert_encoding( $filename, 'UTF-8', 'auto' );
		$fileInfo = EncryptFile::getFileInfo($pathReal);
		$contentType = attach_mime_content_type($pathReal,$filename);

		// Care for Japanese-character-included file name
		$legacy_filename = mb_convert_encoding($filename, 'UTF-8', SOURCE_ENCODING);
		if (LANG == 'ja') {
			switch(UA_NAME . '/' . UA_PROFILE){
			case 'MSIE/default':
				$legacy_filename = mb_convert_encoding($filename, 'SJIS', SOURCE_ENCODING);
				break;
			}
		}
		$utf8filename = mb_convert_encoding($filename, 'UTF-8', SOURCE_ENCODING);

		ini_set('default_charset', '');
		mb_http_output('pass');

		pkwk_common_headers();
		header('Content-Disposition: inline; filename="' . $legacy_filename
			. '"; filename*=utf-8\'\'' . rawurlencode($utf8filename));
		header('Content-Length: ' . $fileInfo->size);
		header('Content-Type: '   . $contentType);

		if( !EncryptFile::downloadFileUser($pathReal) ){
			return array('msg'=>'refserverfiles : unknown error.');
		}
		exit;
	case 'toencrypt':
		if( !EncryptFile::encryptConvertFileUser($pathReal) ){
			return array('msg'=>"refserverfiles : encrypt error. \"{$filename}\"");
		}
		return array('msg'=>"encrypt succeeded. \"{$filename}\"");
	}
	return array('msg'=>'refserverfiles : unknown error.');
}
