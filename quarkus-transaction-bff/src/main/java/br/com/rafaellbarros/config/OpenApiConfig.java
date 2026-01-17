package br.com.rafaellbarros.config;

import jakarta.ws.rs.core.Application;
import org.eclipse.microprofile.openapi.annotations.Components;
import org.eclipse.microprofile.openapi.annotations.OpenAPIDefinition;
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeIn;
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeType;
import org.eclipse.microprofile.openapi.annotations.info.Contact;
import org.eclipse.microprofile.openapi.annotations.info.Info;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.security.SecurityScheme;
import org.eclipse.microprofile.openapi.annotations.servers.Server;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

@OpenAPIDefinition(info = @Info(title = "Sistema de exemplo de transações, curso Quarkus CoffeeandIT",
        version = "1.0.0", contact = @Contact(name = "Fale com CoffeeAndIT",
        email = "coffeeandit@coffeeandit.com.br",
        url = "lb.coffeeandit.com.br")
), tags = {
        @Tag(name = "/v1/transactions", description = "Grupo de API's para manipulação de transações financeiras"),
        @Tag(name = "/v1/limite", description = "Grupo de API's para limites financeiros")
},
        servers = {@Server(url = "http://localhost:8080")},
        security = {@SecurityRequirement(name = "jwt", scopes = {"coffeeandit"})},
        components = @Components(
                securitySchemes = {
                        @SecurityScheme(
                                securitySchemeName = "jwt",
                                type = SecuritySchemeType.HTTP,
                                scheme = "bearer",
                                bearerFormat = "bearer",
                                in = SecuritySchemeIn.HEADER
                            )
                })


)
public class OpenApiConfig extends Application {
}