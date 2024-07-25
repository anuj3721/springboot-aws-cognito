package com.anuj.auth;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class CognitoJWKSProvider {

    private static JsonObject jwks;

    public static JsonObject getJwks(String jwksUrl) throws IOException {
        if (jwks == null) {
            OkHttpClient client = new OkHttpClient.Builder()
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .build();
            Request request = new Request.Builder()
                    .url(jwksUrl)
                    .build();
            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);
                jwks = JsonParser.parseString(response.body().string()).getAsJsonObject();
            }
        }
        return jwks;
    }
}