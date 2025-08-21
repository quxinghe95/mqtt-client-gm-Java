package com.iot.mqtt;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttMessage;

import java.util.Arrays;

@Slf4j
public class MqttCallback implements org.eclipse.paho.client.mqttv3.MqttCallback {

    @Override
    public void connectionLost(Throwable throwable) {
        log.warn("Connection lost. Cause: ", throwable);
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken token) {
        log.info("Callback: delivered message to topics {}", Arrays.asList(token.getTopics()));
    }

    @Override
    public void messageArrived(String topic, MqttMessage message) throws Exception {
        log.info("Callback: received message from topic {}: {}", topic, message.toString());
    }
}
