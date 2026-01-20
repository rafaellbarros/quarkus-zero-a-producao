package br.com.rafaellbarros.api.doc;

import br.com.rafaellbarros.api.dto.RequisicaoTransacaoDTO;
import io.smallrye.mutiny.Uni;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.ParameterIn;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameters;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import static br.com.rafaellbarros.api.doc.DocApiConstants.*;

@Path(TRANSACTION_CONTROLLER_TAG)
@SecurityRequirement(name = "jwt", scopes = {"coffeeandit"})
@Tag(name = TRANSACTION_CONTROLLER_TAG, description = TRANSACTION_CONTROLLER_DESCRIPTION)
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface TransactionApi {

    @POST
    @Operation(description = SAVE_TRANSACTION_DESCRIPTION)
    @APIResponses({
        @APIResponse(responseCode = CREATED_CODE, description = CREATED_DESCRIPTION),
        @APIResponse(responseCode = UNAUTHORIZED_CODE, description = UNAUTHORIZED_DESCRIPTION),
        @APIResponse(responseCode = FORBIDDEN_CODE, description = FORBIDDEN_DESCRIPTION),
        @APIResponse(responseCode = NOT_FOUND_CODE, description = NOT_FOUND_DESCRIPTION)
    })
    Uni<Response> save(@Context UriInfo uriInfo, RequisicaoTransacaoDTO requisicaoTransacaoDTO);

    @GET
    @Path("/{uuid}")
    @Operation(description = FIND_TRANSACTION_DESCRIPTION)
    @APIResponses({
        @APIResponse(responseCode = OK_CODE, description = OK_DESCRIPTION),
        @APIResponse(responseCode = UNAUTHORIZED_CODE, description = UNAUTHORIZED_DESCRIPTION),
        @APIResponse(responseCode = FORBIDDEN_CODE, description = FORBIDDEN_DESCRIPTION),
        @APIResponse(responseCode = NOT_FOUND_CODE, description = NOT_FOUND_DESCRIPTION)
    })
    @Parameter(name = "uuid", in = ParameterIn.PATH, description = TRANSACTION_UUID_PARAM)
    RequisicaoTransacaoDTO findById(@PathParam("uuid") String uuid);

    @PATCH
    @Path("/{uuid}/aprovar")
    @Operation(description = APPROVE_TRANSACTION_DESCRIPTION)
    @APIResponses({
        @APIResponse(responseCode = OK_CODE, description = OK_DESCRIPTION),
        @APIResponse(responseCode = UNAUTHORIZED_CODE, description = UNAUTHORIZED_DESCRIPTION),
        @APIResponse(responseCode = FORBIDDEN_CODE, description = FORBIDDEN_DESCRIPTION),
        @APIResponse(responseCode = NOT_FOUND_CODE, description = NOT_FOUND_DESCRIPTION)
    })
    @Parameters({
        @Parameter(name = "uuid", in = ParameterIn.PATH, description = TRANSACTION_UUID_PARAM),
        @Parameter(name = "x-signature", in = ParameterIn.HEADER, description = TRANSACTION_SIGNATURE_PARAM)
    })
    Response aprovar(@PathParam("uuid") String uuid,
                                   @HeaderParam("x-signature") String signature);

    @DELETE
    @Path("/{uuid}")
    @Operation(description = DELETE_TRANSACTION_DESCRIPTION)
    @APIResponses({
        @APIResponse(responseCode = NO_CONTENT_CODE, description = NO_CONTENT_DESCRIPTION),
        @APIResponse(responseCode = UNAUTHORIZED_CODE, description = UNAUTHORIZED_DESCRIPTION),
        @APIResponse(responseCode = FORBIDDEN_CODE, description = FORBIDDEN_DESCRIPTION),
        @APIResponse(responseCode = NOT_FOUND_CODE, description = NOT_FOUND_DESCRIPTION)
    })
    Response delete(@PathParam("uuid") String uuid);
}