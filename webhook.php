<?php
namespace Phppot;

require_once __DIR__ . "/vendor/stripe/stripe-php/init.php";

$prueba = new StripeService;
$prueba->auth_webhook();

class StripeService
{
  private $user_webhook;
  private $pass_webhook; 

  public function __construct()
  {
    $this->user_webhook = '';
    $this->pass_webhook = '';
  }
  
  public function auth_webhook(){    
    $payload = @file_get_contents('php://input');
    $sig_header = $_SERVER['HTTP_STRIPE_SIGNATURE'];

    $this->create_custom_log('stripe_payload', 'data', $sig_header);

    if (empty($sig_header)){
        header("HTTP/1.1 401 Unauthorized");
        exit();
    }    

    $this->auth_token($sig_header, $payload);    
  }

  function create_custom_log($logname, $string_data = "", $array_data = "")
  {
      $date_name = date("Y-m-d");
      $_logname =  __DIR__ . "/logs/" . $logname . "-" . $date_name . ".log";      
      $date_content = date("Y-m-d H:i:s");
      @file_put_contents($_logname, $date_content . " | " . $string_data . " DATA: " . print_r($array_data, TRUE) . "\n", FILE_APPEND);
  }

  public function auth_token($sig_header, $payload)
  {
        $curl = curl_init(); 
        
        $ip = $this->getClientIpAddress();

        curl_setopt_array($curl, array(
            CURLOPT_URL => "http://localhost/sales/stripewebhooks",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/x-www-form-urlencoded',
                'HTTP_STRIPE_SIGNATURE: ' . $sig_header,
                'user_webhook: ',
                'pass_webhook: ',
                'ip_valid: ' . $ip,
            ),
        ));

        $output = $this->_exec_curl($curl);        

        $this->create_custom_log('sales_payload', 'data',  $output);

        return $output;       
  } 

  function getClientIpAddress()
  {
      if (!empty($_SERVER['HTTP_CLIENT_IP']))   //Checking IP From Shared Internet
      {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
      }
      elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))   //To Check IP is Pass From Proxy
      {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
      }
      else
      {
        $ip = $_SERVER['REMOTE_ADDR'];
      }

      return $ip;
  }

  
    private function _exec_curl($curl)
    {
        $response = curl_exec($curl);
        $output = array();

        // Matching the response to extract cookie value
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi',
            $response, $match_found);

        $cookies = array();
        foreach ($match_found[1] as $item) {
            parse_str($item, $cookie);
            $cookies = array_merge($cookies, $cookie);
        }

        if (!curl_errno($curl)) {
            $curl_info = curl_getinfo($curl);
            switch ($http_code = $curl_info['http_code']) {
                case 200:  # OK
                    $output = json_decode($response, TRUE);
                    break;
                case 201:  # OK
                    $output = json_decode($response, TRUE);
                    break;
                case 400:  # OK
                    $output = json_decode($response, TRUE);
                    break;
                case 401:  # OK
                    $output = json_decode($response, TRUE);
                    break;
                case 423:  # OK
                    $output = json_decode($response, TRUE);
                    break;
                case 500:  # OK
                    $output = json_decode($response, TRUE);
                    break;
                case 422:  # OK
                    $output = json_decode($response, TRUE);
                    break;
                default:
                    echo 'Unexpected HTTP code: ', $http_code, "\n";
            }
            if (!empty($cookies)) {
                $output['_cookies'] = $cookies;
            }
            if (is_null($output)) {
                $output = $response;
            }
        } else {
            echo 'Error:' . curl_error($curl);
        }
        curl_close($curl);
        if (!empty($curl_info)) {
            //echo '<pre>' . $curl_info['url'] . ' --> ' . $curl_info['http_code'] . ': ' . (!empty($response) ? $response : "") . '</pre></br>';
        }

        return $output;
    }

}
