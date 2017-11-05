#include <SPI.h>
#include <MFRC522.h>

#include <ESP8266WiFi.h>
#include <WebSocketsServer.h>
#include <ESP8266WebServer.h>
#include <FS.h>
#include <Hash.h>

ESP8266WebServer server = ESP8266WebServer(80);
WebSocketsServer webSocket = WebSocketsServer(81);

constexpr uint8_t RST_PIN = D4;
constexpr uint8_t SS_PIN = D8;

MFRC522 mfrc522(SS_PIN, RST_PIN);

/*
	operation (all ops use key B as key B is the only key that can RW to value blocks)
	0: nothing to do
	1: read block with key=6 bytes of op data
	2: increment block by change
	3: decrement block by change
*/
uint8_t operation = 0;
uint8_t block = 0;
uint8_t key[6];
int32_t change = 0;

void webSocketEvent(uint8_t num, WStype_t type, uint8_t * payload, size_t length) {
	IPAddress ip;

  switch(type) {
    case WStype_DISCONNECTED:
      Serial.printf("[%u] Disconnected!\n", num);
      break;
    case WStype_CONNECTED:
      ip = webSocket.remoteIP(num);
      Serial.printf("[%u] Connected from %d.%d.%d.%d url: %s\n", num, ip[0], ip[1], ip[2], ip[3], payload);

      // send message to client
      webSocket.sendTXT(num, "Connected");
      break;
    case WStype_BIN:
			switch(payload[0]) {
				case 0x10:
					block = payload[1];
					Serial.print("block changed to ");
					Serial.println(block);
					memcpy(key, &payload[2], 6);
					Serial.print("Key = 0x");
					Serial.print(key[0], HEX);
					Serial.print(key[1], HEX);
					Serial.print(key[2], HEX);
					Serial.print(key[3], HEX);
					Serial.print(key[4], HEX);
					Serial.println(key[5], HEX);
					break;
				case 0x11:
					operation = 1;
					break;
				case 0x12:
					change = ((uint32_t) payload[4] << 24) | ((uint32_t) payload[3] << 16) | ((uint32_t) payload[2] << 8) | payload[1];
					operation = 2;
					break;
				case 0x13:
					change = ((uint32_t) payload[4] << 24) | ((uint32_t) payload[3] << 16) | ((uint32_t) payload[2] << 8) | payload[1];
					operation = 3;
					break;
			}
      break;
  }
}

void setup() {
	pinMode(D2, OUTPUT);

	Serial.begin(115200);
	Serial.println();

	SPI.begin();
	mfrc522.PCD_Init();
	mfrc522.PCD_SetAntennaGain(mfrc522.RxGain_avg);

	WiFi.mode(WIFI_AP);
	WiFi.softAP("MFT", "dont look up");
	WiFi.setOutputPower(5);
	delay(500);

	Serial.print("Soft AP started: ");
	Serial.println(WiFi.softAPIP());

	SPIFFS.begin();
	Serial.println("Initialised SPIFFS");

	server.on("/", []() {
		File file = SPIFFS.open("/index.html", "r");
		Serial.println(server.streamFile(file, "text/html"));
		file.close();
	});

  server.begin();

  webSocket.begin();
  webSocket.onEvent(webSocketEvent);

	Serial.println("Startup finished!");
}

void handle_rfid() {
	uint8_t buf[20];
	MFRC522::MIFARE_Key mf_key;
	MFRC522::StatusCode status;

  //mfrc522.PICC_HaltA();
  //mfrc522.PCD_StopCrypto1();

	if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
		digitalWrite(D2, !digitalRead(D2));
		buf[0] = 0x01;
		memcpy(&buf[1], mfrc522.uid.uidByte, 4);
		webSocket.broadcastBIN(buf, 5);

		if (operation) {

			for (byte i = 0; i < 6; i++) {
        mf_key.keyByte[i] = key[i];
	    }

			Serial.println("Authenticating");
			status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, &mf_key, &(mfrc522.uid));
	    if (status != MFRC522::STATUS_OK) {
				Serial.println("Invalid key");
				buf[0] = 0x02;
        webSocket.broadcastBIN(buf, 1);
				mfrc522.PCD_StopCrypto1();
        return;
	    }
			Serial.println("Key ok");
		}

		if (operation == 1) {
			int32_t val = 0;
			mfrc522.MIFARE_GetValue(block, &val);
			buf[0] = 0x11;
			buf[1] = (val & 0xFF);
			buf[2] = ((val >> 8) & 0xFF);
			buf[3] = ((val >> 16) & 0xFF);
			buf[4] = ((val >> 24) & 0xFF);
			webSocket.broadcastBIN(buf, 5);

			operation = 0;
		}
		else if (operation == 2) {
			Serial.print("Incrementing block ");
			Serial.print(block);
			Serial.print(" by ");
			Serial.println(change);

			status = mfrc522.MIFARE_Increment(block, change);
			if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Increment() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
				mfrc522.PCD_StopCrypto1();
        return;
	    }

			status = mfrc522.MIFARE_Transfer(block);
	    if (status != MFRC522::STATUS_OK) {
	        Serial.print(F("MIFARE_Transfer() failed: "));
	        Serial.println(mfrc522.GetStatusCodeName(status));
					mfrc522.PCD_StopCrypto1();
	        return;
	    }

			operation = 1;
		}
		else if (operation == 3) {
			Serial.print("Decrementing block ");
			Serial.print(block);
			Serial.print(" by ");
			Serial.println(change);

			status = mfrc522.MIFARE_Decrement(block, change);
			if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Decrement() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
				mfrc522.PCD_StopCrypto1();
        return;
	    }

			status = mfrc522.MIFARE_Transfer(block);
	    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Transfer() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
				mfrc522.PCD_StopCrypto1();
        return;
	    }
			operation = 1;
		}

		mfrc522.PCD_StopCrypto1();
	}
}

void loop() {
	static uint32_t last_ping = 0;
	static uint32_t last_blink = 0;
	handle_rfid();

	if ((millis() - last_ping) > 500) {
		webSocket.broadcastTXT("Alive!");
		last_ping = millis();
	}

	if (WiFi.softAPgetStationNum() == 0) {
		if ((millis() - last_blink) > 2000) {
			digitalWrite(D2, !digitalRead(D2));

			last_blink = millis();
		}
	}
	else {
		if ((millis() - last_blink) > 500) {
			digitalWrite(D2, !digitalRead(D2));

			last_blink = millis();
		}
	}

  webSocket.loop();
  server.handleClient();
}
