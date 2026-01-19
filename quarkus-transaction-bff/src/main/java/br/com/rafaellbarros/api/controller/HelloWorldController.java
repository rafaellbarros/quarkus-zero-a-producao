package br.com.rafaellbarros.api.controller;

import br.com.rafaellbarros.api.doc.HelloWorldApi;
import org.eclipse.microprofile.config.inject.ConfigProperty;


public class HelloWorldController implements HelloWorldApi {

    @ConfigProperty(name = "greeting.message", defaultValue = "Não achamos")
    private String message;

    @Override
    public String coffee() {
        return " Oi " + message;
    }
}
