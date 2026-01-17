package br.com.rafaellbarros.api.dto;

public class CpfDto {

    public String getCpf() {
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    private String cpf;
    private boolean valid;
}
