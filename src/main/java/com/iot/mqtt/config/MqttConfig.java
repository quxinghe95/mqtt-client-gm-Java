package com.iot.mqtt.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "iot.mqtt")
public class MqttConfig {

    private String host;

    private Integer timeout;

    private Integer keepalive;

    private String clientId;

    private String caCrtFile;

    private String subCaCrtFile;

    private String clientEncCrt;
    private String clientEncKey;
    private String clientSignCrt;
    private String clientSignKey;
}
