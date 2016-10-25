package pareshvaniya.com.apiman.rest.client;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;
import org.json.JSONObject;
import org.keycloak.OAuth2Constants;
import org.keycloak.constants.ServiceUrlConstants;

public class ApimanKeyCloakClient {

//http://localhost:8080/RESTfulExample/json/product/get
	public static void main(String[] args) throws ClientProtocolException, IOException, JSONException {

		//http://127.0.0.1:8080/auth/realms/stottie/protocol/openid-connect/token  -H "Content-Type: application/x-www-form-urlencoded" -d "username=rincewind" -d "password=apiman" -d "grant_type=password" -d "client_id=apiman"
		//http://10.0.7.110:8080/auth/realms/mobileoauth/protocol/openid-connect/token
		//mobileapp
		
		  HttpClient client = new DefaultHttpClient();


	        try {
	            HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri("http://127.0.0.1:8080" + "/auth")
	                    .path(ServiceUrlConstants.TOKEN_PATH).build("stottie"));
	            List <NameValuePair> formparams = new ArrayList <NameValuePair>();
	            formparams.add(new BasicNameValuePair("username", "rincewind"));
	            formparams.add(new BasicNameValuePair("password", "apiman"));
	            formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "password"));
	            formparams.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, "apiman"));
            
	            /*HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri("http://10.0.7.110:8080" + "/auth")
	                    .path(ServiceUrlConstants.TOKEN_PATH).build("mobileoauth"));
	            List <NameValuePair> formparams = new ArrayList <NameValuePair>();
	            formparams.add(new BasicNameValuePair("username", "paresh"));
	            formparams.add(new BasicNameValuePair("password", "paresh123"));
	            formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "password"));
	            formparams.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, "mobileapp"));
	            formparams.add(new BasicNameValuePair("username", "paresh"));
	            formparams.add(new BasicNameValuePair("password", "paresh123"));
	            formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "password"));
	            formparams.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, "apiman"));
	            */
	            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
	            post.setEntity(form);

	            HttpResponse response = client.execute(post);
	            int status = response.getStatusLine().getStatusCode();
	            HttpEntity entity = response.getEntity();
	            if (status != 200) {
	                String json = getContent(entity);
	                throw new IOException("Bad status: " + status + " response: " + json);
	            }
	            if (entity == null) {
	                throw new IOException("No Entity");
	            }
	            String json = getContent(entity);
	            
	            JSONObject jObject  = new JSONObject(json);
	            
	            jObject.getString("access_token");
	            
	            String access_token = jObject.getString("access_token");
	            
	            System.out.println("access_token = "+access_token);
	            
	            
	            /*HttpGet get = new HttpGet("https://127.0.0.1:8443/apiman-gateway/Newcastle/EchoAPI/1.0?access_token="+access_token);

	         

	            HttpResponse response1 = client.execute(get);
	            int status1 = response1.getStatusLine().getStatusCode();
	            HttpEntity entity1 = response1.getEntity();
	            if (status1 != 200) {
	                String json1 = getContent(entity1);
	                throw new IOException("Bad status: " + status1 + " response: " + json1);
	            }
	            if (entity == null) {
	                throw new IOException("No Entity");
	            }
	            String json1 = getContent(entity1);
	          
	            System.out.println("json1 = "+json1);*/
	            new ApimanKeyCloakClient().testIt("http://127.0.0.1:8443/apiman-gateway/Newcastle/EchoAPI/1.0?access_token="+access_token);

	            
	            
	            
	            
	        } finally {
	            client.getConnectionManager().shutdown();
	        }
	}
	        public static String getContent(HttpEntity entity) throws IOException {
	            if (entity == null) return null;
	            InputStream is = entity.getContent();
	            try {
	                ByteArrayOutputStream os = new ByteArrayOutputStream();
	                int c;
	                while ((c = is.read()) != -1) {
	                    os.write(c);
	                }
	                byte[] bytes = os.toByteArray();
	                String data = new String(bytes);
	                return data;
	            } finally {
	                try {
	                    is.close();
	                } catch (IOException ignored) {

	                }
	            }

	        }

	        
	        private TrustManager[ ] get_trust_mgr() {
	            TrustManager[ ] certs = new TrustManager[ ] {
	               new X509TrustManager() {
	                  public X509Certificate[ ] getAcceptedIssuers() { return null; }
	                  public void checkClientTrusted(X509Certificate[ ] certs, String t) { }
	                  public void checkServerTrusted(X509Certificate[ ] certs, String t) { }
	                }
	             };
	             return certs;
	         }

	         private void testIt(String httpsurl){
	            String https_url = httpsurl;
	            URL url;
	            try {

	       	    // Create a context that doesn't check certificates.
	                   SSLContext ssl_ctx = SSLContext.getInstance("TLS");
	                   TrustManager[ ] trust_mgr = get_trust_mgr();
	                   ssl_ctx.init(null,                // key manager
	                                trust_mgr,           // trust manager
	                                new SecureRandom()); // random number generator
	                   HttpsURLConnection.setDefaultSSLSocketFactory(ssl_ctx.getSocketFactory());

	       	    url = new URL(null, https_url, new sun.net.www.protocol.https.Handler());
	       	    HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

	       	    // Guard against "bad hostname" errors during handshake.
	                   con.setHostnameVerifier(new HostnameVerifier() {
	                       public boolean verify(String host, SSLSession sess) {
	                           if (host.equals("127.0.0.1")) return true;
	                           else return false;
	                       }
	                   });

	       	    //dumpl all cert info
	       	    print_https_cert(con);

	       	    //dump all the content
	       	    print_content(con);

	       	 } catch (MalformedURLException e) {
	       		e.printStackTrace();
	       	 } catch (IOException e) {
	       		e.printStackTrace();
	       	 }catch (NoSuchAlgorithmException e) {
	       		e.printStackTrace();
	       	 }catch (KeyManagementException e) {
	       		e.printStackTrace();
	             }
	          }

	         private void print_https_cert(HttpsURLConnection con){
	            if(con!=null){

	            try {

	       	System.out.println("Response Code : " + con.getResponseCode());
	       	System.out.println("Cipher Suite : " + con.getCipherSuite());
	       	System.out.println("\n");

	       	Certificate[] certs = con.getServerCertificates();
	       	for(Certificate cert : certs){
	       	  System.out.println("Cert Type : " + cert.getType());
	       	  System.out.println("Cert Hash Code : " + cert.hashCode());
	       	  System.out.println("Cert Public Key Algorithm : " + cert.getPublicKey().getAlgorithm());
	       	  System.out.println("Cert Public Key Format : " + cert.getPublicKey().getFormat());
	       	  System.out.println("\n");
	       	}


	            } catch (SSLPeerUnverifiedException e) {
	       	  e.printStackTrace();
	            } catch (IOException e){
	       	  e.printStackTrace();
	            }
	          }
	         }

	         private void print_content(HttpsURLConnection con){
	           if(con!=null){

	           try {

	       	System.out.println("****** Content of the URL ********");

	       	BufferedReader br =
	       		new BufferedReader(
	       			new InputStreamReader(con.getInputStream()));

	       	String input;

	       	while ((input = br.readLine()) != null){
	       	   System.out.println(input);
	       	}
	       	br.close();

	            } catch (IOException e) {
	       	e.printStackTrace();
	            }
	          }
	         }
	            
	
	}