package com.kmods.toba;

import android.app.ProgressDialog;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.androidnetworking.AndroidNetworking;
import com.androidnetworking.common.ANResponse;

import org.json.JSONObject;

import java.io.File;

public class LoginActivity extends AppCompatActivity {
    private static final String LOGG = "LOGGED";
    private static final String SIGN = "F7f059d4e72f7ac6f";
    private static final String HOST = "http://10.0.2.2/TOBA";

    private EditText mPass;
    private EditText mUsername;
    private EditText mMessage;
    private boolean isLogged;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        if(!Utils.isFileExist(getCacheDir() + "/Keys/")){
            new File(getCacheDir() + "/Keys/").mkdir();
        }

        mPass = findViewById(R.id.password);
        mUsername = findViewById(R.id.username);
        mMessage = findViewById(R.id.message);
        Button mLogin = findViewById(R.id.login);

        isLogged = getIntent().getBooleanExtra(LOGG, false);
        if(isLogged){
            mMessage.setVisibility(View.VISIBLE);
            mUsername.setVisibility(View.GONE);
            mPass.setVisibility(View.GONE);
            mLogin.setText("Send!");
        }

        mLogin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(isLogged){
                    if (!mMessage.getText().toString().isEmpty()) {
                        new BackgroudProc().execute(mMessage.getText().toString());
                    } else {
                        Toast.makeText(LoginActivity.this, "Insufficent data, Fill Everything!", Toast.LENGTH_LONG).show();
                    }
                } else {
                    if (!mUsername.getText().toString().isEmpty() || !mPass.getText().toString().isEmpty()) {
                        new BackgroudProc().execute(mUsername.getText().toString(), mPass.getText().toString());
                    } else {
                        Toast.makeText(LoginActivity.this, "Insufficent data, Fill Everything!", Toast.LENGTH_LONG).show();
                    }
                }
            }
        });
    }

    private class BackgroudProc extends AsyncTask<String, Void, String> {
        ProgressDialog pd;

        @Override
        protected void onPreExecute() {
            pd = new ProgressDialog(LoginActivity.this);
            pd.setCancelable(false);
            pd.setTitle("Processing!");
            pd.show();
        }

        @Override
        protected String doInBackground(String... strings) {
            if(isLogged){
                String token = messageToken(strings[0]);
                Object[] acktoken = getMsgStatus(token);
                if(acktoken != null) {
                    Log.e("TOBA-Log","Server's Message Ack Response: " + acktoken[0] + "\n");
                    if((boolean)acktoken[1]) {
                        return VerifyandShowMsg((String) acktoken[0]);
                    }
                    return (String) acktoken[0];
                }
                return "Message Error!";
            } else {
                if (getServerPublickey()) {
                    String token = loginToken(strings[0], strings[1]);
                    Object[] acktoken = getLoginStatus(token);
                    if(acktoken != null) {
                        Log.e("TOBA-Log","Server's Login Ack Response: " + acktoken[0] + "\n");
                        if((boolean)acktoken[1]) {
                            if (VerifyandStoreData((String) acktoken[0])) {
                                return "Login Ok!";
                            }
                        }
                        return (String) acktoken[0];
                    }
                    return "Login Failed!";
                }
            }
            return "Error!";
        }

        @Override
        protected void onPostExecute(String s) {
            pd.dismiss();
            Toast.makeText(LoginActivity.this, s, Toast.LENGTH_LONG).show();
            if(s.equals("Login Ok!")){
                Intent intent = new Intent(LoginActivity.this, LoginActivity.class);
                intent.putExtra(LOGG, true);
                LoginActivity.this.startActivity(intent);
            }
        }

        boolean getServerPublickey(){
            try {
                ANResponse serverpublic = AndroidNetworking.get(HOST + "/serverpublic").build().executeForString();
                if(serverpublic.isSuccess()){
                    String keypath = getCacheDir() + "/Keys/ServerPublicKey.puk";
                    String puk = serverpublic.getResult().toString();
                    if(Utils.isFileExist(keypath)){
                        String mypuk = Utils.toBase64(Utils.getFileInBytes(keypath));
                        if(!Utils.SHA256(mypuk).equals(Utils.SHA256(puk))){
                            Utils.writeToFile(keypath, Utils.fromBase64(puk));
                            Log.e("TOBA-Log","Got ServerPublicKey!\n");
                        } else {
                            Log.e("TOBA-Log","ServerPublicKey is Already There!\n");
                        }
                    } else {
                        Utils.writeToFile(keypath, Utils.fromBase64(puk));
                        Log.e("TOBA-Log","Got ServerPublicKey!\n");
                    }
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }

        String loginToken(String uname, String pass){
            try {
                JSONObject token = new JSONObject();
                token.put("id", 1);

                JSONObject data = new JSONObject();
                data.put("userid", uname);
                data.put("password", pass);
                data.put("clientsignature", SIGN);

                token.put("Data", RSA.encrypt(data.toString(),getCacheDir() + "/Keys/ServerPublicKey.puk"));

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

        Object[] getLoginStatus(String token){
            Log.e("TOBA-Log","Client Sent Login Token: " + token + "\n");
            ANResponse response = AndroidNetworking.post(HOST + "/login")
                    .addBodyParameter("token", Utils.toBase64(token)).build().executeForString();
            if(response.isSuccess()){
                if(response.getOkHttpResponse().header("Content-type", "").contains("text/plain")){
                    return new Object[] {response.getResult().toString(), false};
                }
                return new Object[] {Utils.fromBase64String(response.getResult().toString()), true};
            }
            return null;
        }

        boolean VerifyandStoreData(String acktoken) {
            try {
                if(acktoken.isEmpty() || acktoken.contains("Fail")){
                    return false;
                }
                String privatekeypath = getCacheDir() + "/Keys/PrivateKey.puk";
                String authdatapath = getCacheDir() + "/Keys/AuthData.dat";
                JSONObject token = new JSONObject(acktoken);
                String data = (String) token.get("Data");
                JSONObject hash = (JSONObject) token.get("Hash");
                token = new JSONObject(Utils.fromBase64String(data));

                String privatekey = (String) token.get("private");
                String authdata = (String) token.get("authdata");
                String serversignature = (String) token.get("serversignature");

                Log.e("TOBA-Log","Server Signature: " + serversignature + "\n");

                if (Utils.SHA256(data) != hash.get("hash")) {
                    if ((!Utils.isFileExist(privatekeypath) || !Utils.isFileExist(authdatapath))) {
                        Utils.writeToFile(privatekeypath, Utils.fromBase64(privatekey));
                        Utils.writeToFile(authdatapath, Utils.fromBase64(authdata));

                        Log.e("TOBA-Log","Private Key Stored!\n");
                        Log.e("TOBA-Log","AuthData Stored!\n");
                    } else {
                        Log.e("TOBA-Log","Privatekey is Already There!\n");
                        Log.e("TOBA-Log","AuthData is Already There!\n");
                    }
                    return true;
                } else {
                    Log.e("TOBA-Log","Hash Match Failed!\n");
                    return false;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }

        String messageToken(String msg){
            try {
                JSONObject token = new JSONObject();
                token.put("id", 3);

                JSONObject data = new JSONObject();
                data.put("message", msg);
                data.put("clientsignature", SIGN);

                token.put("Data", RSA.encrypt(data.toString(),getCacheDir() + "/Keys/ServerPublicKey.puk"));
                token.put("authdata", Utils.toBase64(Utils.getFileInBytes(getCacheDir() + "/Keys/AuthData.dat")));

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

        Object[] getMsgStatus(String token){
            Log.e("TOBA-Log","Client Sent Message Token: " + token + "\n");
            ANResponse response = AndroidNetworking.post(HOST + "/message")
                    .addBodyParameter("token", Utils.toBase64(token)).build().executeForString();
            if(response.isSuccess()){
                if(response.getOkHttpResponse().header("Content-type", "").contains("text/plain")){
                    return new Object[] {response.getResult().toString(), false};
                }
                return new Object[] {Utils.fromBase64String(response.getResult().toString()), true};
            }
            return null;
        }

        String VerifyandShowMsg(String acktoken) {
            try {
                JSONObject token = new JSONObject(acktoken);
                String data = (String) token.get("Data");
                JSONObject hash = (JSONObject) token.get("Hash");

                if(Utils.SHA256(data) != hash.get("hash")) {
                    //data = RSA.decrypt(data, "Keys/PrivateKey.prk");
                    Log.e("TOBA-Log","Message: " + data + "!\n");
                    return data;
                } else {
                    return "Hash Match Failed!";
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return "Failed to Parse Message!";
        }
    }

    private LinearLayout.LayoutParams setParams() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT);
        params.gravity = Gravity.CENTER_VERTICAL;
        return params;
    }
}
