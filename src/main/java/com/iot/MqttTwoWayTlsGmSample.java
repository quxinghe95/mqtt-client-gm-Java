package com.iot;

import com.iot.mqtt.MqttCallback;
import com.iot.mqtt.SSLUtils;
import com.iot.mqtt.config.MqttConfig;
import lombok.extern.slf4j.Slf4j;
import net.tongsuo.TongsuoProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.conscrypt.Conscrypt;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.SSLSocketFactory;
import java.security.Security;

@Slf4j
@SpringBootApplication
public class MqttTwoWayTlsGmSample implements ApplicationRunner {

    private static final String SUNEC = "SunEC";
    private static final String TOPIC = "java-mqtt/tls-gm";
    private static final int QoS = 1;
    private static final boolean CLEAN_SESSION = true;
    private static final boolean AUTOMATIC_RECONNECT = true;
    private static final boolean HTTPS_HOSTNAME_VERIFICATION_ENABLED = false;
    private static final String CIPHER_SUITE_GM = "ECC-SM2-SM4-GCM-SM3";

    @Autowired
    private MqttConfig config;

    public static void main(String[] args) {
        Conscrypt.setUseEngineSocketByDefault(false);
        Security.removeProvider(SUNEC);
        Security.addProvider(new TongsuoProvider());
        Security.addProvider(new BouncyCastleProvider());

        SpringApplication.run(MqttTwoWayTlsGmSample.class, args);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        MqttClient client = null;

        try {
            client = new MqttClient(config.getHost(), config.getClientId(), new MemoryPersistence());
            MqttCallback callBack = new MqttCallback();
            client.setCallback(callBack);
            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(CLEAN_SESSION);
            options.setUserName(config.getClientId());
            options.setConnectionTimeout(config.getTimeout());
            options.setKeepAliveInterval(config.getKeepalive());
            options.setAutomaticReconnect(AUTOMATIC_RECONNECT);
            options.setHttpsHostnameVerificationEnabled(HTTPS_HOSTNAME_VERIFICATION_ENABLED);
            options.setEnabledCipherSuites(new String[]{CIPHER_SUITE_GM});

            SSLSocketFactory sslSocketFactory =
                    SSLUtils.createSocketFactory(
                            config.getCaCrtFile(),
                            config.getClientEncCrt(),
                            config.getClientEncKey(),
                            config.getClientSignCrt(),
                            config.getClientSignKey());
            options.setSocketFactory(sslSocketFactory);
            client.connect(options);

            if (!client.isConnected()) {
                log.error("Failed to connect to broker: {}", config.getHost());
                return;
            }
            log.info("Connected to broker: {}", config.getHost());

            client.subscribe(TOPIC, QoS);
            log.info("Subscribed to topic: {}", TOPIC);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (client != null) {
                try {
                    client.disconnect();
                    client.close();
                } catch (MqttException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
