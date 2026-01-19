package br.com.rafaellbarros.api.doc;

public final class DocApiConstants {
    // Códigos de status HTTP
    static final String OK_CODE = "200";
    static final String OK_DESCRIPTION = "Request successful";

    static final String CREATED_CODE = "201";
    static final String CREATED_DESCRIPTION = "Resource created successfully";

    static final String NO_CONTENT_CODE = "204";
    static final String NO_CONTENT_DESCRIPTION = "Request successful, no content to return";

    static final String BAD_REQUEST_CODE = "400";
    static final String BAD_REQUEST_DESCRIPTION = "The request was malformed, omitting mandatory attributes, "
            + "either in the payload or through attributes in the URL.";

    static final String UNAUTHORIZED_CODE = "401";
    static final String UNAUTHORIZED_DESCRIPTION = "Authentication error or token not provided/expired";

    static final String FORBIDDEN_CODE = "403";
    static final String FORBIDDEN_DESCRIPTION = "Authorization error - user lacks required permissions";

    static final String NOT_FOUND_CODE = "404";
    static final String NOT_FOUND_DESCRIPTION = "The resource could not be found.";

    static final String INTERNAL_SERVER_ERROR_CODE = "500";
    static final String INTERNAL_SERVER_ERROR_DESCRIPTION = "An error occurred in the API gateway or microservice.";

    // Paths dos controllers
    static final String HELLO_CONTROLLER_PATH_TAG = "/v1/coffee";
    static final String TRANSACTION_CONTROLLER_TAG = "/v1/transactions";
    static final String LIMITE_CONTROLLER_TAG = "/v1/limite";

    // Descrições dos controllers
    static final String HELLO_CONTROLLER_DESCRIPTION = "API de Hello World";
    static final String TRANSACTION_CONTROLLER_DESCRIPTION = "Grupo de APIs para manipulação de transações financeiras";
    static final String LIMITE_CONTROLLER_DESCRIPTION = "Grupo de API's para limites financeiros";

    // Descrições dos endpoints
    static final String HELLO_WORLD_DESCRIPTION = "API responsável por retornar o nome para Hello";
    static final String SAVE_TRANSACTION_DESCRIPTION = "API responsável por criar uma transação financeira";
    static final String FIND_TRANSACTION_DESCRIPTION = "API responsável por procurar uma transação financeira";
    static final String APPROVE_TRANSACTION_DESCRIPTION = "API responsável por aprovar uma transação financeira";
    static final String DELETE_TRANSACTION_DESCRIPTION = "API responsável por deletar uma transação financeira";
    static final String FIND_LIMITE_DESCRIPTION = "API responsável por recuperar um limite de uma agencia e conta";

    // Descrições de parâmetros
    static final String TRANSACTION_UUID_PARAM = "UUID v4 da transação";
    static final String TRANSACTION_SIGNATURE_PARAM = "Assinatura da transação";
    static final String AGENCIA_PARAM = "Código da Agência";
    static final String CONTA_PARAM = "Código da Conta";

    private DocApiConstants() {
        throw new UnsupportedOperationException("Instantiation not allowed");
    }
}