import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;

public class TOBA {
    private static final String UNAME = "KP7742";
    private static final String PASS = "1234";
    private static final String SIGN = "F7f059d4e72f7ac6f";
    private static final String HOST = "http://localhost/TOBA";

    private static boolean isDataChanged = false;
    private static JSONParser parser;

    public static void main(String[] args) {
        try {
            parser = new JSONParser();

            getServerPublickey();//Get Server's Public Key

            //Send Login Token
            String token = loginToken();
            System.out.println("Client Sent Login Token: " + token + "\n");
            token = Utils.toBase64(token);

            //Parse Authentication Ack Token
            String acktoken = Utils.fromBase64String(getLoginStatus(token));
            System.out.println("Server's Login Ack Response: " + acktoken + "\n");

            //Store Privatekey and AuthData
            VerifyandStoreData(acktoken);

            //Send Message Token
            token = messageToken("Hii");
            System.out.println("Client Sent Message Token: " + token + "\n");
            token = Utils.toBase64(token);

            //Parse Message Ack Token
            acktoken = Utils.fromBase64String(getMsgStatus(token));
            System.out.println("Server's Message Ack Response: " + acktoken + "\n");

            //Verify and Show Response Message
            VerifyandShowMsg(acktoken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void getServerPublickey(){
        try {
            HttpURLConnection urlConnection = (HttpURLConnection) new URL(HOST + "/serverpublic").openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.setDoInput(true);
            String puk = Utils.readStream(urlConnection.getInputStream());
            if(Utils.isFileExist("Keys/ServerPublicKey.puk")){
                String mypuk = Utils.toBase64(Utils.getFileInBytes("Keys/ServerPublicKey.puk"));
                if(!Utils.SHA256(mypuk).equals(Utils.SHA256(puk))){
                    Utils.writeToFile("Keys/ServerPublicKey.puk", Utils.fromBase64(puk));
                    System.out.println("Got ServerPublicKey!\n");
                    isDataChanged = true;
                } else {
                    System.out.println("ServerPublicKey is Already There!\n");
                }
            } else {
                Utils.writeToFile("Keys/ServerPublicKey.puk", Utils.fromBase64(puk));
                System.out.println("Got ServerPublicKey!\n");
                isDataChanged = true;
            }
            urlConnection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getLoginStatus(String token){
        try {
            String s;
            HttpURLConnection urlConnection = (HttpURLConnection) new URL(HOST + "/login").openConnection();
            urlConnection.setRequestMethod("POST");
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);
            urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            String postParameters = "token=" + token;
            urlConnection.setFixedLengthStreamingMode(postParameters.getBytes().length);
            PrintWriter out = new PrintWriter(urlConnection.getOutputStream());
            out.print(postParameters);
            out.close();
            s = Utils.readStream(urlConnection.getInputStream());
            urlConnection.disconnect();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String loginToken(){
        try {
            JSONObject token = new JSONObject();
            token.put("id", 1);

            JSONObject data = new JSONObject();
            data.put("userid", UNAME);
            data.put("password", PASS);
            data.put("clientsignature", SIGN);

            token.put("Data", RSA.encrypt(data.toString(),"Keys/ServerPublicKey.puk"));

            JSONObject hash = new JSONObject();
            hash.put("algo","SHA-256");
            hash.put("hash", Utils.SHA256(data.toString()));

            token.put("Hash", hash);
            token.put("validity", 12000);
            return token.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private static void VerifyandStoreData(String acktoken) throws Exception {
        JSONObject token = (JSONObject) parser.parse(acktoken);
        String data = (String) token.get("Data");
        JSONObject hash = (JSONObject) token.get("Hash");
        token = (JSONObject) new JSONParser().parse(Utils.fromBase64String(data));

        String privatekey = (String) token.get("private");
        String authdata = (String) token.get("authdata");
        String serversignature = (String) token.get("serversignature");

        System.out.println("Server Signature: " + serversignature + "\n");

        if(Utils.SHA256(data) != hash.get("hash")) {
            if((!Utils.isFileExist("Keys/PrivateKey.puk") || !Utils.isFileExist("Keys/AuthData.dat")) && isDataChanged) {
                Utils.writeToFile("Keys/PrivateKey.prk", Utils.fromBase64(privatekey));
                Utils.writeToFile("Keys/AuthData.dat", Utils.fromBase64(authdata));

                System.out.println("Private Key Stored!\n");
                System.out.println("AuthData Stored!\n");
            } else {
                System.out.println("Privatekey is Already There!\n");
                System.out.println("AuthData is Already There!\n");
            }
        } else {
            throw new Exception("Hash Match Failed!");
        }
    }

    private static String messageToken(String msg){
        try {
            JSONObject token = new JSONObject();
            token.put("id", 3);

            JSONObject data = new JSONObject();
            data.put("message", msg);
            data.put("clientsignature", SIGN);

            token.put("Data", RSA.encrypt(data.toString(),"Keys/ServerPublicKey.puk"));
            token.put("authdata", Utils.toBase64(Utils.getFileInBytes("Keys/AuthData.dat")));

            JSONObject hash = new JSONObject();
            hash.put("algo","SHA-256");
            hash.put("hash", Utils.SHA256(data.toString()));

            token.put("Hash", hash);
            token.put("validity", 12000);
            return token.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private static String getMsgStatus(String token){
        try {
            String s;
            HttpURLConnection urlConnection = (HttpURLConnection) new URL(HOST + "/message").openConnection();
            urlConnection.setRequestMethod("POST");
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);
            urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            String postParameters = "token=" + token;
            urlConnection.setFixedLengthStreamingMode(postParameters.getBytes().length);
            PrintWriter out = new PrintWriter(urlConnection.getOutputStream());
            out.print(postParameters);
            out.close();
            s = Utils.readStream(urlConnection.getInputStream());
            urlConnection.disconnect();
            return s;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void VerifyandShowMsg(String acktoken) throws Exception {
        JSONObject token = (JSONObject) parser.parse(acktoken);
        String data = (String) token.get("Data");
        JSONObject hash = (JSONObject) token.get("Hash");

        if(Utils.SHA256(data) != hash.get("hash")) {
            //data = RSA.decrypt(data, "Keys/PrivateKey.prk");
            System.out.println("Message: " + data + "!\n");
        } else {
            throw new Exception("Hash Match Failed!");
        }
    }
}
