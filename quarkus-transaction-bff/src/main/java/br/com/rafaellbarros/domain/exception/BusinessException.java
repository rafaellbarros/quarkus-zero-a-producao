package br.com.rafaellbarros.domain.exception;

import jakarta.ws.rs.core.Response;
import lombok.Getter;

public class BusinessException extends RuntimeException {

    @Getter
    private final Response.Status status;
    
    public BusinessException(String message) {
        this(message, Response.Status.BAD_REQUEST);
    }
    
    public BusinessException(String message, Response.Status status) {
        super(message);
        this.status = status;
    }

}