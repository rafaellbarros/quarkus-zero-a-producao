package br.com.rafaellbarros.domain.service;

import br.com.rafaellbarros.api.dto.CpfDTO;
import br.com.rafaellbarros.api.dto.FailedMessageDTO;
import br.com.rafaellbarros.api.dto.RequisicaoTransacaoDTO;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.quarkus.redis.client.RedisClient;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import io.smallrye.reactive.messaging.kafka.api.OutgoingKafkaRecordMetadata;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.jose.JWT;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.reactive.messaging.Channel;
import org.eclipse.microprofile.reactive.messaging.Emitter;
import org.eclipse.microprofile.reactive.messaging.Message;
import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;


@ApplicationScoped
public class TransactionService {


    public static final String VALOR_TRANSACOES = "valorTransacoes";


    // @Inject
    // @RestClient
    // CPFService cpfService;

    public static final int MINUTES = 15;

    @Inject
    RedisClient redisClient;

    @Inject
    @Channel("transaction")
    Emitter<RequisicaoTransacaoDTO> transactionEmitter;

    private ObjectMapper objectMapper = null;
    private static final Logger LOG = Logger.getLogger(TransactionService.class);

    @Inject
    JsonWebToken accessToken;

    @ConfigProperty(name = "app.encrypt")
    boolean isEncrypt;

    @ConfigProperty(name = "app.secret")
    private String secret;


    @Inject
    MeterRegistry registry;

    private AtomicReference<BigDecimal> valorTransacoes = new AtomicReference<>(BigDecimal.ZERO);
    private AtomicReference<BigDecimal> contagemTransacoes = new AtomicReference<>(BigDecimal.ZERO);

    @PostConstruct
    void initMetrics() {
        // Registrar gauges no Micrometer
        registry.gauge("valor_transacoes",
                valorTransacoes,
                ref -> ref.get().doubleValue());

        registry.gauge("contagem_transacoes",
                contagemTransacoes,
                ref -> ref.get().doubleValue());
    }



    @Transactional
    public Uni<Optional<RequisicaoTransacaoDTO>> save(final RequisicaoTransacaoDTO requisicaoTransacaoDTO) {
        // Usa uma worker thread para operações bloqueantes
        return Uni.createFrom().item(requisicaoTransacaoDTO)
                .runSubscriptionOn(Infrastructure.getDefaultWorkerPool())
                .onItem().transform(dto -> {
                    try {
                        // Operações síncronas na worker thread
                        dto.setUuid(UUID.randomUUID());
                        dto.setData(LocalDateTime.now());
                        dto.aceitaProcessamento();

                        return dto;
                    } catch (Exception e) {
                        LOG.error("Erro ao preparar transação: " + e.getMessage());
                        throw new RuntimeException(e);
                    }
                })
                .onItem().transformToUni(dto -> {
                    // Salva no Redis (ainda na worker thread)
                    return saveToRedis(dto);
                })
                .onItem().invoke(dto -> {
                    // Tarefas assíncronas em background
                    sendToKafkaAsync(dto);
                    recordMetricsAsync(dto);

                    LOG.info("Transação processada: " + dto.getUuid());
                })
                .onItem().transform(dto -> Optional.of(dto))
                .onFailure().recoverWithItem(throwable -> {
                    LOG.error("Falha ao processar transação: " + throwable.getMessage());
                    return Optional.empty();
                });
    }


    private void validarCPF(final RequisicaoTransacaoDTO requisicaoTransacaoDTO) {
        try {
            final CpfDTO cpfDto = new CpfDTO(); // cpfService.validarCPF(requisicaoTransacaoDTO.getBeneficiario().getCPF().toString());
            if (!cpfDto.isValid()) {
                throw new BadRequestException("CPF Inválido.");
            }
        } catch (final Exception e) {  // ResteasyWebApplicationException
            LOG.error(e.getMessage());
        }
    }

    @Transactional
    public Optional<RequisicaoTransacaoDTO> aprovarTransacao(final RequisicaoTransacaoDTO requisicaoTransacaoDTO, final String signature) {
        if (requisicaoTransacaoDTO.getSignature().equals(signature)) {
            if (validateSignature(requisicaoTransacaoDTO, signature)) return update(requisicaoTransacaoDTO);
        }
        throw new NotAuthorizedException(Response.status(401).build());
    }

    private boolean validateSignature(final RequisicaoTransacaoDTO requisicaoTransacaoDTO, final String signature) {
        if (isEncrypt) {
            requisicaoTransacaoDTO.confirmadaUsuario();
            return true;
        } else {
            var jsonObject = JWT.parse(signature);
            var payload = jsonObject.getMap().get("payload");
            final long exp = ((JsonObject) payload).getLong("exp");
            var expirationTime =
                    LocalDateTime.ofInstant(Instant.ofEpochMilli(exp * 1000),
                            TimeZone.getDefault().toZoneId());
            if (expirationTime.isAfter(LocalDateTime.now())) {
                var jti = ((JsonObject) payload).getString("jti");
                if (requisicaoTransacaoDTO.getUuid().toString().equals(jti)) {
                    requisicaoTransacaoDTO.confirmadaUsuario();
                    return true;
                }
            }

            return false;

        }

    }

    @Transactional
    protected  Optional<RequisicaoTransacaoDTO> update(final RequisicaoTransacaoDTO requisicaoTransacaoDTO) {
        try {
            sendKafka(requisicaoTransacaoDTO);
            var payload = getObjectMapper().writeValueAsString(requisicaoTransacaoDTO);
            redisClient.set(Arrays.asList(requisicaoTransacaoDTO.getUuid().toString(), payload));
            redisClient.save();
            LOG.info("Transação atualizada " + requisicaoTransacaoDTO);
            return Optional.of(requisicaoTransacaoDTO);
        } catch (JsonProcessingException e) {
            LOG.error(e.getMessage());
        }

        return Optional.empty();
    }

    @Transactional
    public boolean delete(final String uuid) {
        final Optional<RequisicaoTransacaoDTO> requisicaoTransacaoDTO = find(uuid);
        if (requisicaoTransacaoDTO.isPresent()) {
            LOG.info("DELETANDO recurso " + uuid);
            redisClient.del(List.of(uuid));
            return true;
        }
        return false;
    }

    private void sendKafka(final RequisicaoTransacaoDTO requisicaoTransacaoDTO) {
        transactionEmitter.send(
                Message.of(requisicaoTransacaoDTO).addMetadata(OutgoingKafkaRecordMetadata.<String>builder()
                        .withKey(requisicaoTransacaoDTO.getUuid().toString())
                        .withHeaders(new RecordHeaders().add("x-signature", requisicaoTransacaoDTO.getSignature().getBytes(StandardCharsets.UTF_8)))
                        .build()));
    }

    private void signature(final RequisicaoTransacaoDTO requisicaoTransacaoDTO) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        var signatureKeys = new HashMap<String, Object>();
        signatureKeys.put("agencia", requisicaoTransacaoDTO.getBeneficiario().getAgencia());
        signatureKeys.put("conta", requisicaoTransacaoDTO.getBeneficiario().getConta());
        signatureKeys.put("codigoBanco", requisicaoTransacaoDTO.getBeneficiario().getCodigoBanco());
        signatureKeys.put("cpf", requisicaoTransacaoDTO.getBeneficiario().getCPF());
        signatureKeys.put("valor", requisicaoTransacaoDTO.getValor());
        signatureKeys.put("contaOrigem", requisicaoTransacaoDTO.getConta().getCodigoConta());
        signatureKeys.put("id", requisicaoTransacaoDTO.getUuid().toString());
        signatureKeys.put("jti", requisicaoTransacaoDTO.getUuid().toString());
        signatureKeys.put("agenciaOrigem", requisicaoTransacaoDTO.getConta().getCodigoAgencia());
        if (isEncrypt) {

            requisicaoTransacaoDTO.setSignature(Jwt.claims(signatureKeys)
                    .expiresIn(Duration.ofMinutes(MINUTES)).upn(accessToken.getClaim("azp")).jwe()
                    .encrypt(getPublicKey()));

        } else
            requisicaoTransacaoDTO.setSignature(Jwt.claims(signatureKeys)
                    .expiresIn(Duration.ofMinutes(MINUTES)).upn(accessToken.getClaim("azp")).sign());

    }

    public Optional<RequisicaoTransacaoDTO> find(String uuid) {

        var response = redisClient.get(uuid);
        LOG.info("find: " + response.toString());
        if (Objects.nonNull(response)) {
            try {
                return Optional.of(getObjectMapper().readValue(response.toString(), RequisicaoTransacaoDTO.class));
            } catch (JsonProcessingException e) {
                LOG.error(e.getMessage());
            }
        }
        return Optional.empty();
    }

    private ObjectMapper getObjectMapper() {
        if (Objects.isNull(objectMapper)) {
            objectMapper = new ObjectMapper();
            objectMapper.findAndRegisterModules();
        }
        return objectMapper;
    }

    private PrivateKey getPrivateKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        try (InputStream inputStream = getClass().getResourceAsStream("/privateKey.pem");
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            var privateKeyContent = reader.lines()
                    .collect(Collectors.joining(System.lineSeparator()));
            privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            return kf.generatePrivate(keySpecPKCS8);
        }
    }

    private PublicKey getPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        try (InputStream inputStream = getClass().getResourceAsStream("/publicKey.pem");
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            var publicKeyContent = reader.lines()
                    .collect(Collectors.joining(System.lineSeparator()));
            publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
            return (RSAPublicKey) kf.generatePublic(keySpecX509);
        }
    }

    private Uni<RequisicaoTransacaoDTO> saveToRedis(RequisicaoTransacaoDTO dto) {
        return Uni.createFrom().item(() -> {
            try {
                var payload = getObjectMapper().writeValueAsString(dto);
                // Usa o cliente Redis assíncrono
                redisClient.append(dto.getUuid().toString(), payload);

                redisClient.save();

                return dto;
            } catch (JsonProcessingException e) {
                LOG.error("Erro JSON: " + e.getMessage());
                throw new RuntimeException(e);
            } catch (Exception e) {
                LOG.error("Erro Redis: " + e.getMessage());
                throw new RuntimeException(e);
            }
        });
    }

    private void sendToKafkaAsync(RequisicaoTransacaoDTO dto) {
        try {
            // Envia de forma assíncrona
            CompletionStage<Void> sendStage = transactionEmitter.send(dto);

            // Adiciona tratamento de sucesso
            sendStage.thenRun(() -> {
                LOG.debug("Mensagem enviada com sucesso para Kafka: " + dto.getUuid());
            });

            // Adiciona tratamento de erro
            sendStage.exceptionally(throwable -> {
                LOG.error("Falha ao enviar para Kafka: " + throwable.getMessage());

                // Implementa retry manual
                retryKafkaSend(dto, 1, throwable);
                return null;
            });

        } catch (Exception e) {
            LOG.error("Erro ao preparar envio para Kafka: " + e.getMessage());
            retryKafkaSend(dto, 1, e);
        }
    }

    private void retryKafkaSend(RequisicaoTransacaoDTO dto, int attempt, Throwable originalError) {
        if (attempt >= 3) {
            LOG.error("Máximo de retries atingido para UUID: " + dto.getUuid());
            logFailedKafkaMessage(dto, originalError);
            return;
        }

        // Agenda retry com delay exponencial
        long delay = (long) (1000 * Math.pow(2, attempt - 1)); // 1s, 2s, 4s

        Uni.createFrom().voidItem()
                .onItem().delayIt().by(Duration.ofMillis(delay))
                .runSubscriptionOn(Infrastructure.getDefaultWorkerPool())
                .subscribe().with(
                        ignored -> {
                            try {
                                LOG.info("Tentando reenviar para Kafka (tentativa " + (attempt + 1) + "): " + dto.getUuid());
                                CompletionStage<Void> retryStage = transactionEmitter.send(dto);

                                retryStage.exceptionally(throwable -> {
                                    retryKafkaSend(dto, attempt + 1, throwable);
                                    return null;
                                });

                            } catch (Exception e) {
                                retryKafkaSend(dto, attempt + 1, e);
                            }
                        },
                        failure -> {
                            LOG.error("Erro ao agendar retry: " + failure.getMessage());
                            logFailedKafkaMessage(dto, originalError);
                        }
                );
    }

    private void recordMetricsAsync(RequisicaoTransacaoDTO dto) {
        Uni.createFrom().item(dto)
                .runSubscriptionOn(Infrastructure.getDefaultWorkerPool())
                .subscribe().with(
                        item -> {
                            Counter.builder("transactions.total")
                                    .description("Total de transações processadas")
                                    .tag("tipo", dto.getTipoTransacao().name())
                                    .register(registry)
                                    .increment();
                        },
                        failure -> LOG.warn("Falha ao registrar métricas: " + failure.getMessage())
                );
    }

    private void logFailedKafkaMessage(RequisicaoTransacaoDTO dto, Throwable throwable) {
        // Pode salvar em uma lista no Redis para reprocessamento posterior
        try {
            String failedMessage = getObjectMapper().writeValueAsString(new FailedMessageDTO(dto, throwable.getMessage()));
            redisClient.append("failed-kafka-messages", failedMessage);
        } catch (JsonProcessingException e) {
            LOG.error("Não foi possível registrar mensagem falha do Kafka: " + e.getMessage());
        }
    }

}
