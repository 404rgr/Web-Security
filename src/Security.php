<?php
namespace WebSec\WebSecurity;
class Security{
    public static $redirect = False;
    public static $save_log = True;
    public $only_allow_files = [];
    private static $client_ip;
    private $sqli_list;
    private $xss_list;
    public function __construct(){
      self::$client_ip = $_SERVER['REMOTE_ADDR'];
      $this->sqli_list = [
	 'order(.*)by',
	 'union(.*)select',
	 'union(.*)distinct',
	 'union(.*)distinctrow',
	 'information_schema',
	 'table_schema',
	 'concat\(',
	 '@hostname',
	 '@version_compile_machine',
	 '@version_compile_os',
	 'make_set\(',
      ];
      $this->xss_list = [
	 'javascript',
	 'onload',
	 '\.cookie',
	 'alert',
	 '<script>(.*)</script>',
	 '<(.*)>',
      ];
    }
    public function filter(){
	foreach($_GET as $key => $value){
	  $_GET[$key] = str_replace(["'",'"'],["",""], $value);
	}
        foreach($_POST as $key => $value){
          $_POST[$key] = str_replace(["'",'"'],["",""], $value);
        }
    }
    public function protect_sqli(){
      $detect = false;
      foreach([$_GET,$_POST] as $__){
        foreach($__ as $value){
         foreach($this->sqli_list as $exp){
          if ($this->search($exp,$value)){
            //die("Exit!! ".$exp.' '.$value);
            $detect = True;
          }
         }
        }
      }
      if($detect == True){
	      $this->block("SQL Injection");
      }
    }
    public function protect_xss(){
      $detect = false;
      foreach([$_GET,$_POST] as $__){
        foreach($__ as $value){
		foreach($this->xss_list as $exp){
          if (self::search($exp, $value)){
            //die("Exit!! ".$exp.' '.$value);
            $detect = True;
          }
         }
        }
      }
      if($detect == True){
              self::block("XSS");
      }
    }
    public function files_protect(){
      if($this->only_allow_files){
              $detect = False;
	      foreach($_FILES as $file){
		$path = pathinfo(strtolower($file['name']), PATHINFO_EXTENSION);
		if(in_array($path,$this->only_allow_files)){
                  $detect = False;
                }else{
                  $detect = True;
                }
	      }
              if ($detect == True){
                  $this->block("Prohibited file types");
              }else{
		  //pass
              }
      }
    }
    private function search($str, $raw){
      preg_match("~$str~i", $raw, $result);
      return $result;
    }
    private static function block($reason=""){
       if(self::$save_log){
           error_log('IP: '.self::$client_ip.' | AttackType: '.$reason."\r\n", 3, __DIR__.'/user.log');
       }
       if(self::$redirect){
        header("Location: ".self::$redirect);
        echo '<meta http-equiv="refresh" content="0;url='.$this->redirect.'">'; //alternative
        exit();
       }else{
	       self::default_block($reason);
       }
    }
    private static function default_block($reason=''){
       //echo "disini template html\nreason: $reason";
       $P403 = base64_decode('DQo8IURPQ1RZUEUgaHRtbD4NCjxodG1sIGxhbmc9ImVuIiA+DQo8aGVhZD4NCiAgPG1ldGEgY2hhcnNldD0iVVRGLTgiPg0KICA8dGl0bGU+QWNjZXNzIEZvcmJpZGRlbiB8IEVycm9yIDQwMzwvdGl0bGU+DQogIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvbm9ybWFsaXplLzUuMC4wL25vcm1hbGl6ZS5taW4uY3NzIj4NCiAgPHN0eWxlPg0KQGltcG9ydCB1cmwoImh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzP2ZhbWlseT1Nb250c2VycmF0OjQwMCw0MDBpLDcwMCIpOw0KYm9keSB7DQogIGRpc3BsYXk6IGZsZXg7DQogIGFsaWduLWl0ZW1zOiBjZW50ZXI7DQogIGp1c3RpZnktY29udGVudDogY2VudGVyOw0KICBoZWlnaHQ6IDEwMHZoOw0KICB3aWR0aDogMTAwdnc7DQogIGJhY2tncm91bmQ6ICNlY2VmZjE7DQogIGZvbnQtZmFtaWx5OiBNb250c2VycmF0LCBzYW5zLXNlcmlmOw0KfQ0KDQouY29udGFpbmVyIHsNCiAgYmFja2dyb3VuZDogd2hpdGU7DQogIGhlaWdodDogYXV0bzsNCiAgd2lkdGg6IDQwdnc7DQogIHBhZGRpbmc6IDEuNXJlbTsNCiAgYm94LXNoYWRvdzogMHB4IDNweCAxNXB4IHJnYmEoMCwgMCwgMCwgMC4yKTsNCiAgYm9yZGVyLXJhZGl1czogMC41cmVtOw0KICB0ZXh0LWFsaWduOiBjZW50ZXI7DQp9DQouY29udGFpbmVyIGgxIHsNCiAgZm9udC1zaXplOiAxLjI1cmVtOw0KICBtYXJnaW46IDA7DQogIG1hcmdpbi10b3A6IDFyZW07DQogIGNvbG9yOiAjMjYzMjM4Ow0KICBvcGFjaXR5OiAwOw0KICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTAuMXJlbSk7DQogIC13ZWJraXQtYW5pbWF0aW9uOiBmYWRlSW4gMXMgZm9yd2FyZHMgMS41czsNCiAgICAgICAgICBhbmltYXRpb246IGZhZGVJbiAxcyBmb3J3YXJkcyAxLjVzOw0KfQ0KLmNvbnRhaW5lciBwIHsNCiAgbWFyZ2luOiAwOw0KICBtYXJnaW4tdG9wOiAwLjVyZW07DQogIGNvbG9yOiAjNTQ2ZTdhOw0KICBvcGFjaXR5OiAwOw0KICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTAuMXJlbSk7DQogIC13ZWJraXQtYW5pbWF0aW9uOiBmYWRlSW4gMXMgZm9yd2FyZHMgMS43NXM7DQogICAgICAgICAgYW5pbWF0aW9uOiBmYWRlSW4gMXMgZm9yd2FyZHMgMS43NXM7DQp9DQoNCkBtZWRpYSBzY3JlZW4gYW5kIChtYXgtd2lkdGg6IDc2OHB4KSB7DQogIC5jb250YWluZXIgew0KICAgIHdpZHRoOiA1MHZ3Ow0KICB9DQp9DQpAbWVkaWEgc2NyZWVuIGFuZCAobWF4LXdpZHRoOiA2MDBweCkgew0KICAuY29udGFpbmVyIHsNCiAgICB3aWR0aDogNjB2dzsNCiAgfQ0KfQ0KQG1lZGlhIHNjcmVlbiBhbmQgKG1heC13aWR0aDogNTAwcHgpIHsNCiAgLmNvbnRhaW5lciB7DQogICAgd2lkdGg6IDgwdnc7DQogIH0NCn0NCkAtd2Via2l0LWtleWZyYW1lcyBmYWRlSW4gew0KICBmcm9tIHsNCiAgICB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoMXJlbSk7DQogICAgb3BhY2l0eTogMDsNCiAgfQ0KICB0byB7DQogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKDByZW0pOw0KICAgIG9wYWNpdHk6IDE7DQogIH0NCn0NCkBrZXlmcmFtZXMgZmFkZUluIHsNCiAgZnJvbSB7DQogICAgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKDFyZW0pOw0KICAgIG9wYWNpdHk6IDA7DQogIH0NCiAgdG8gew0KICAgIHRyYW5zZm9ybTogdHJhbnNsYXRlWSgwcmVtKTsNCiAgICBvcGFjaXR5OiAxOw0KICB9DQp9DQouZm9yYmlkZGVuLXNpZ24gew0KICBtYXJnaW46IGF1dG87DQogIHdpZHRoOiA0LjY2NjY2NjY2NjdyZW07DQogIGhlaWdodDogNC42NjY2NjY2NjY3cmVtOw0KICBib3JkZXItcmFkaXVzOiA1MCU7DQogIGRpc3BsYXk6IGZsZXg7DQogIGFsaWduLWl0ZW1zOiBjZW50ZXI7DQogIGp1c3RpZnktY29udGVudDogY2VudGVyOw0KICBiYWNrZ3JvdW5kLWNvbG9yOiAjZWY1MzUwOw0KICAtd2Via2l0LWFuaW1hdGlvbjogZ3JvdyAxcyBmb3J3YXJkczsNCiAgICAgICAgICBhbmltYXRpb246IGdyb3cgMXMgZm9yd2FyZHM7DQp9DQoNCkAtd2Via2l0LWtleWZyYW1lcyBncm93IHsNCiAgZnJvbSB7DQogICAgdHJhbnNmb3JtOiBzY2FsZSgxKTsNCiAgfQ0KICB0byB7DQogICAgdHJhbnNmb3JtOiBzY2FsZSgxKTsNCiAgfQ0KfQ0KDQpAa2V5ZnJhbWVzIGdyb3cgew0KICBmcm9tIHsNCiAgICB0cmFuc2Zvcm06IHNjYWxlKDEpOw0KICB9DQogIHRvIHsNCiAgICB0cmFuc2Zvcm06IHNjYWxlKDEpOw0KICB9DQp9DQouZm9yYmlkZGVuLXNpZ246OmJlZm9yZSB7DQogIHBvc2l0aW9uOiBhYnNvbHV0ZTsNCiAgYmFja2dyb3VuZC1jb2xvcjogd2hpdGU7DQogIGJvcmRlci1yYWRpdXM6IDUwJTsNCiAgY29udGVudDogIiI7DQogIHdpZHRoOiA0cmVtOw0KICBoZWlnaHQ6IDRyZW07DQogIHRyYW5zZm9ybTogc2NhbGUoMCk7DQogIC13ZWJraXQtYW5pbWF0aW9uOiBncm93MiAwLjVzIGZvcndhcmRzIDAuNXM7DQogICAgICAgICAgYW5pbWF0aW9uOiBncm93MiAwLjVzIGZvcndhcmRzIDAuNXM7DQp9DQoNCkAtd2Via2l0LWtleWZyYW1lcyBncm93MiB7DQogIGZyb20gew0KICAgIHRyYW5zZm9ybTogc2NhbGUoMCk7DQogIH0NCiAgdG8gew0KICAgIHRyYW5zZm9ybTogc2NhbGUoMSk7DQogIH0NCn0NCg0KQGtleWZyYW1lcyBncm93MiB7DQogIGZyb20gew0KICAgIHRyYW5zZm9ybTogc2NhbGUoMCk7DQogIH0NCiAgdG8gew0KICAgIHRyYW5zZm9ybTogc2NhbGUoMSk7DQogIH0NCn0NCi5mb3JiaWRkZW4tc2lnbjo6YWZ0ZXIgew0KICBjb250ZW50OiAiIjsNCiAgei1pbmRleDogMjsNCiAgcG9zaXRpb246IGFic29sdXRlOw0KICB3aWR0aDogNHJlbTsNCiAgaGVpZ2h0OiAwLjMzMzMzMzMzMzNyZW07DQogIHRyYW5zZm9ybTogc2NhbGV5KDApIHJvdGF0ZVooMGRlZyk7DQogIGJhY2tncm91bmQ6ICNlZjUzNTA7DQogIC13ZWJraXQtYW5pbWF0aW9uOiBncm93MyAwLjVzIGZvcndhcmRzIDFzOw0KICAgICAgICAgIGFuaW1hdGlvbjogZ3JvdzMgMC41cyBmb3J3YXJkcyAxczsNCn0NCg0KQC13ZWJraXQta2V5ZnJhbWVzIGdyb3czIHsNCiAgZnJvbSB7DQogICAgdHJhbnNmb3JtOiBzY2FsZXkoMCkgcm90YXRlWigwZGVnKTsNCiAgfQ0KICB0byB7DQogICAgdHJhbnNmb3JtOiBzY2FsZXkoMSkgcm90YXRlWigtNDVkZWcpOw0KICB9DQp9DQoNCkBrZXlmcmFtZXMgZ3JvdzMgew0KICBmcm9tIHsNCiAgICB0cmFuc2Zvcm06IHNjYWxleSgwKSByb3RhdGVaKDBkZWcpOw0KICB9DQogIHRvIHsNCiAgICB0cmFuc2Zvcm06IHNjYWxleSgxKSByb3RhdGVaKC00NWRlZyk7DQogIH0NCn0NCiAgPC9zdHlsZT4NCjwvaGVhZD4NCjxib2R5Pg0KPCEtLSBwYXJ0aWFsOmluZGV4LnBhcnRpYWwuaHRtbCAtLT4NCjxkaXYgY2xhc3M9ImNvbnRhaW5lciI+DQoJPGRpdiBjbGFzcz0iZm9yYmlkZGVuLXNpZ24iPjwvZGl2Pg0KCTxoMT5BY2Nlc3MgdG8gdGhpcyBwYWdlIGlzIHJlc3RyaWN0ZWQuPC9oMT4NCgk8cD5Zb3UgYXJlIGJsb2NrZWQgZm9yIHNvbWUgcmVhc29uLDxicj4gUGxlYXNlIGNvbnRhY3QgdGhlIGFkbWluaXN0cmF0b3Igbm93ITwvcD4NCiAgICAgICAgPHA+WW91ciBJUDoge3tjbGllbnRfaXB9fTwvcD4NCjwvZGl2Pg0KPCEtLSBwYXJ0aWFsIC0tPg0KDQo8L2JvZHk+DQo8L2h0bWw+DQo=');
       $pausi = $P403; //self::raw(); //\websec\WebSecurity\P403::raw(); //file_get_contents(__DIR__.'/403.php');
       echo str_replace("{{client_ip}}",self::$client_ip,$pausi);
       die();
    }
}
