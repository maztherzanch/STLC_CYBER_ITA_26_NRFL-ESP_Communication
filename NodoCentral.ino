#include <SPI.h>
#include <LoRa.h>

// ============================================================================
// 1. CONFIGURACIÓN DE IDENTIDAD (CAMBIAR SEGÚN LA PLACA A PROGRAMAR)
//    0 = CENTRAL  |  1 = NODO_A  |  2 = NODO_B
// ============================================================================
#define ROL_DISPOSITIVO 0

#if ROL_DISPOSITIVO == 0
const String MI_ID          = "CENTRAL";
String       DESTINO_ID     = "ALL";
const bool   ES_CENTRAL     = true;
#elif ROL_DISPOSITIVO == 1
const String MI_ID          = "NODO_A";
String       DESTINO_ID     = "NODO_B";
const bool   ES_CENTRAL     = false;
#else
const String MI_ID          = "NODO_B";
String       DESTINO_ID     = "NODO_A";
const bool   ES_CENTRAL     = false;
#endif

// ============================================================================
// 2. CLAVES CRIPTOGRÁFICAS Y TABLA DE CANALES LORA SEGUROS
// ============================================================================
// Clave maestra exclusiva de la Central para órdenes de canal y difusión global
const String CLAVE_MAESTRA_CENTRAL = "BastWAN_Central_MasterKey_2026_Aero#!";
// Clave de sesión activa (cambia dinámicamente cuando la Central desplaza a un canal seguro)
String claveSesionActiva           = "BastWAN_FrutigerAero_SecretKey_2026!#";

// 4 Canales Físicos LoRa (Frecuencia + SyncWord de aislamiento hardware)
const int   TOTAL_CANALES = 4;
const long  TABLA_FRECUENCIAS[TOTAL_CANALES] = { 915000000, 915500000, 916000000, 916500000 };
const uint8_t TABLA_SYNCWORDS[TOTAL_CANALES] = { 0x12,      0x34,      0x56,      0x78      };

int canalActualIdx = 0;
bool parAutorizadoEnCanal = true;

uint32_t contadorPaquetes = 0;
String ultimoPaqueteValidoEnviado = "";

// Registro Anti-Replay independiente por cada emisor
String ultimoNonceCentral = "";
String ultimoNonceNodoA   = "";
String ultimoNonceNodoB   = "";

// ============================================================================
// 3. MOTOR CRIPTOGRÁFICO SHA-256 + HMAC + CIFRADO DE FLUJO DE LA CENTRAL
// ============================================================================
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    for (int i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (int i = 16; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (int i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_raw(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t block[64];
    size_t i = 0;
    while (len - i >= 64) {
        sha256_transform(state, data + i);
        i += 64;
    }
    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        sha256_transform(state, block);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    uint64_t bitlen = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) block[63 - j] = (bitlen >> (j * 8)) & 0xFF;
    sha256_transform(state, block);
    for (int j = 0; j < 8; j++) {
        out[j * 4]     = (state[j] >> 24) & 0xFF;
        out[j * 4 + 1] = (state[j] >> 16) & 0xFF;
        out[j * 4 + 2] = (state[j] >> 8) & 0xFF;
        out[j * 4 + 3] = state[j] & 0xFF;
    }
}

// Calcula HMAC-SHA256 usando la clave especificada (Maestra de Central o Sesión de Canal)
String calcularFirmaHMACConClave(String mensaje, String claveUsada) {
    uint8_t keyBlock[64];
    memset(keyBlock, 0, 64);
    if (claveUsada.length() > 64) {
        sha256_raw((const uint8_t*)claveUsada.c_str(), claveUsada.length(), keyBlock);
    } else {
        memcpy(keyBlock, claveUsada.c_str(), claveUsada.length());
    }

    uint8_t o_key_pad[64], i_key_pad[64];
    for (int i = 0; i < 64; i++) {
        o_key_pad[i] = keyBlock[i] ^ 0x5c;
        i_key_pad[i] = keyBlock[i] ^ 0x36;
    }

    size_t msgLen = mensaje.length();
    uint8_t* innerData = (uint8_t*)malloc(64 + msgLen);
    memcpy(innerData, i_key_pad, 64);
    memcpy(innerData + 64, mensaje.c_str(), msgLen);

    uint8_t innerHash[32];
    sha256_raw(innerData, 64 + msgLen, innerHash);
    free(innerData);

    uint8_t outerData[96];
    memcpy(outerData, o_key_pad, 64);
    memcpy(outerData + 64, innerHash, 32);

    uint8_t finalHash[32];
    sha256_raw(outerData, 96, finalHash);

    char hexOut[17];
    for (int i = 0; i < 8; i++) {
        sprintf(hexOut + (i * 2), "%02x", finalHash[i]);
    }
    hexOut[16] = '\0';
    return String(hexOut);
}

String calcularFirmaHMAC(String mensaje) {
    return calcularFirmaHMACConClave(mensaje, claveSesionActiva);
}

// Cifrado Simétrico en Flujo SHA-256 (CTR-Keystream) exclusivo de la Central
String cifrarPayloadCentralHex(String textoClaro, String llave, String nonce) {
    size_t len = textoClaro.length();
    String salidaHex = "";
    uint8_t keystream[32];

    for (size_t i = 0; i < len; i++) {
        if (i % 32 == 0) {
            String semillaBloque = llave + "|" + nonce + "|" + String(i / 32);
            sha256_raw((const uint8_t*)semillaBloque.c_str(), semillaBloque.length(), keystream);
        }
        uint8_t byteCifrado = ((uint8_t)textoClaro[i]) ^ keystream[i % 32];
        char buf[3];
        sprintf(buf, "%02X", byteCifrado);
        salidaHex += buf;
    }
    return salidaHex;
}

uint8_t hexCharAByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

String descifrarPayloadCentralHex(String hexCifrado, String llave, String nonce) {
    size_t numBytes = hexCifrado.length() / 2;
    String textoClaro = "";
    uint8_t keystream[32];

    for (size_t i = 0; i < numBytes; i++) {
        if (i % 32 == 0) {
            String semillaBloque = llave + "|" + nonce + "|" + String(i / 32);
            sha256_raw((const uint8_t*)semillaBloque.c_str(), semillaBloque.length(), keystream);
        }
        uint8_t b = (hexCharAByte(hexCifrado[i * 2]) << 4) | hexCharAByte(hexCifrado[i * 2 + 1]);
        char c = (char)(b ^ keystream[i % 32]);
        textoClaro += c;
    }
    return textoClaro;
}

// ============================================================================
// 4. CONTROL DE RADIO LORA, CAMBIO DE CANAL SEGURO Y PATRÓN SOS
// ============================================================================
void reportarEstadoSistema() {
    String resumenKey = calcularFirmaHMACConClave("KEY_FINGERPRINT", claveSesionActiva).substring(0, 8);
    resumenKey.toUpperCase();
    float mhz = TABLA_FRECUENCIAS[canalActualIdx] / 1000000.0;
    Serial.println("SYS_INFO|" + MI_ID + "|" + DESTINO_ID + "|CH_" + String(canalActualIdx) + "|" + String(mhz, 1) + "MHz|" + resumenKey);
}

void sintonizarCanalFisicoLoRa(int nuevoCanalIdx, String nuevaClaveSesion) {
    if (nuevoCanalIdx < 0 || nuevoCanalIdx >= TOTAL_CANALES) return;
    canalActualIdx = nuevoCanalIdx;
    if (nuevaClaveSesion.length() > 0) {
        claveSesionActiva = nuevaClaveSesion;
    }

    LoRa.idle();
    LoRa.setFrequency(TABLA_FRECUENCIAS[canalActualIdx]);
    LoRa.setSyncWord(TABLA_SYNCWORDS[canalActualIdx]);
    LoRa.receive();

    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_BUILTIN, HIGH); delay(35);
        digitalWrite(LED_BUILTIN, LOW);  delay(35);
    }

    float mhz = TABLA_FRECUENCIAS[canalActualIdx] / 1000000.0;
    String resumenKey = calcularFirmaHMACConClave("KEY_FINGERPRINT", claveSesionActiva).substring(0, 8);
    resumenKey.toUpperCase();
    Serial.println("SYS_CH_CHANGED|CH_" + String(canalActualIdx) + "|" + String(mhz, 1) + "MHz|0x" + String(TABLA_SYNCWORDS[canalActualIdx], HEX) + "|" + resumenKey);
    reportarEstadoSistema();
}

void ejecutarMorseSOS() {
    int cortos[3] = {120, 120, 120};
    int largos[3] = {360, 360, 360};
    for (int i = 0; i < 3; i++) { digitalWrite(LED_BUILTIN, HIGH); delay(cortos[i]); digitalWrite(LED_BUILTIN, LOW); delay(100); }
    delay(150);
    for (int i = 0; i < 3; i++) { digitalWrite(LED_BUILTIN, HIGH); delay(largos[i]); digitalWrite(LED_BUILTIN, LOW); delay(100); }
    delay(150);
    for (int i = 0; i < 3; i++) { digitalWrite(LED_BUILTIN, HIGH); delay(cortos[i]); digitalWrite(LED_BUILTIN, LOW); delay(100); }
}

void transmitirCrudoLoRa(String trama) {
    digitalWrite(RFM_SWITCH, LOW);
    LoRa.beginPacket();
    LoRa.print(trama);
    LoRa.endPacket();
    digitalWrite(RFM_SWITCH, HIGH);
    LoRa.receive();
}

String generarNuevoNonce() {
    contadorPaquetes++;
    String nonce = String(millis() & 0xFFFF, HEX) + String(contadorPaquetes, HEX);
    nonce.toUpperCase();
    return nonce;
}

// Envía paquete estándar firmado con la clave de sesión del canal activo
void enviarPaqueteLoRaADestino(String destinoEspecifico, String tipo, String payload) {
    String nonce = generarNuevoNonce();
    String cuerpo = MI_ID + "|" + destinoEspecifico + "|" + nonce + "|" + tipo + "|" + payload;
    String firmaHash = calcularFirmaHMACConClave(cuerpo, claveSesionActiva);
    String paqueteCompleto = cuerpo + "|" + firmaHash;

    ultimoPaqueteValidoEnviado = paqueteCompleto;
    transmitirCrudoLoRa(paqueteCompleto);

    Serial.println("SYS_TX|" + tipo + "|" + firmaHash + "|" + nonce + "|" + payload);
}

void enviarPaqueteLoRa(String tipo, String payload) {
    enviarPaqueteLoRaADestino(DESTINO_ID, tipo, payload);
}

// Exclusivo CENTRAL: Crea una clave dinámica, cifra el ticket de canal y desplaza a los nodos por ID
void centralDesplazarNodosACanalSeguro(int nuevoCanal, String idNodo1, String idNodo2) {
    if (!ES_CENTRAL) {
        Serial.println("SEC_ALERT|NO_AUTORIZADO|0|Solo CENTRAL puede desplazar canales");
        return;
    }
    if (nuevoCanal < 0 || nuevoCanal >= TOTAL_CANALES) return;

    // Generar clave de sesión dinámica única para ese canal
    String semilla = String(millis(), HEX) + "_" + String(contadorPaquetes + 77, HEX);
    String nuevaClaveSesion = "AERO_CH" + String(nuevoCanal) + "_" + calcularFirmaHMACConClave(semilla, CLAVE_MAESTRA_CENTRAL);

    // Ticket claro: CANAL|CLAVE_SESION|NODO_1|NODO_2
    String ticketClaro = String(nuevoCanal) + "|" + nuevaClaveSesion + "|" + idNodo1 + "|" + idNodo2;
    String nonce = generarNuevoNonce();
    String ticketCifradoHex = cifrarPayloadCentralHex(ticketClaro, CLAVE_MAESTRA_CENTRAL, nonce);

    String cuerpo = "CENTRAL|ALL|" + nonce + "|CH_SHIFT|" + ticketCifradoHex;
    String firmaMaestra = calcularFirmaHMACConClave(cuerpo, CLAVE_MAESTRA_CENTRAL);
    String paqueteOrden = cuerpo + "|" + firmaMaestra;

    // Emitir ráfaga doble para garantizar que ambos nodos reciban la orden de salto
    transmitirCrudoLoRa(paqueteOrden);
    delay(120);
    transmitirCrudoLoRa(paqueteOrden);

    Serial.println("SYS_TX|CH_SHIFT|" + firmaMaestra + "|" + nonce + "|CH_" + String(nuevoCanal) + "->" + idNodo1 + "<->" + idNodo2);

    // La Central también se desplaza al nuevo canal para supervisar y poder enviar mensajes globales
    delay(90);
    sintonizarCanalFisicoLoRa(nuevoCanal, nuevaClaveSesion);
}

// Exclusivo CENTRAL: Difusión de mensaje global cifrado a NODO_A y NODO_B simultáneamente
void centralEnviarMensajeGlobal(String mensajeGlobalClaro) {
    if (!ES_CENTRAL) {
        Serial.println("SEC_ALERT|NO_AUTORIZADO|0|Solo CENTRAL puede emitir mensajes globales");
        return;
    }
    String nonce = generarNuevoNonce();
    String payloadCifradoHex = cifrarPayloadCentralHex(mensajeGlobalClaro, CLAVE_MAESTRA_CENTRAL, nonce);

    String cuerpo = "CENTRAL|ALL|" + nonce + "|GLOBAL|" + payloadCifradoHex;
    String firmaMaestra = calcularFirmaHMACConClave(cuerpo, CLAVE_MAESTRA_CENTRAL);
    String paqueteGlobal = cuerpo + "|" + firmaMaestra;

    transmitirCrudoLoRa(paqueteGlobal);
    Serial.println("SYS_TX|GLOBAL|" + firmaMaestra + "|" + nonce + "|" + mensajeGlobalClaro);
}

// ============================================================================
// 5. RECEPCIÓN, VALIDACIÓN DE ID, ENRUTAMIENTO Y ANTI-SUPLANTACIÓN
// ============================================================================
bool esOrigenConocido(String id) {
    return (id == "CENTRAL" || id == "NODO_A" || id == "NODO_B");
}

bool verificarYActualizarNonce(String origen, String nonce) {
    if (origen == "CENTRAL") {
        if (nonce == ultimoNonceCentral) return false;
        ultimoNonceCentral = nonce;
        return true;
    } else if (origen == "NODO_A") {
        if (nonce == ultimoNonceNodoA) return false;
        ultimoNonceNodoA = nonce;
        return true;
    } else if (origen == "NODO_B") {
        if (nonce == ultimoNonceNodoB) return false;
        ultimoNonceNodoB = nonce;
        return true;
    }
    return false;
}

void procesarPaqueteLoRa(String paquete, int rssi) {
    int p1 = paquete.indexOf('|');
    int p2 = paquete.indexOf('|', p1 + 1);
    int p3 = paquete.indexOf('|', p2 + 1);
    int p4 = paquete.indexOf('|', p3 + 1);
    int p5 = paquete.lastIndexOf('|');

    if (p1 == -1 || p2 == -1 || p3 == -1 || p4 == -1 || p5 == -1 || p5 <= p4) {
        Serial.println("SEC_ALERT|FORMATO_INVALIDO|" + String(rssi) + "|Trama corrupta");
        return;
    }

    String origen  = paquete.substring(0, p1);
    String destino = paquete.substring(p1 + 1, p2);
    String nonce   = paquete.substring(p2 + 1, p3);
    String tipo    = paquete.substring(p3 + 1, p4);
    String payload = paquete.substring(p4 + 1, p5);
    String firmaRx = paquete.substring(p5 + 1);

    // 1. Verificar que el emisor pertenezca a la red (CENTRAL, NODO_A o NODO_B)
    if (!esOrigenConocido(origen) || origen == MI_ID) {
        if (origen != MI_ID) {
            Serial.println("SEC_ALERT|INTRUSO_EXTERNO|" + String(rssi) + "|Origen no autorizado: " + origen);
        }
        return;
    }

    // 2. Si somos la CENTRAL y llega un paquete entre NODO_A y NODO_B (o un RELAY), podemos monitorearlo o enrutarlo
    bool esParaMi = (destino == MI_ID || destino == "ALL");

    // Verificar firma HMAC (CH_SHIFT y GLOBAL usan la Clave Maestra de la Central)
    String cuerpo = paquete.substring(0, p5);
    bool usaClaveMaestra = (tipo == "CH_SHIFT" || tipo == "GLOBAL");
    String claveVerificacion = usaClaveMaestra ? CLAVE_MAESTRA_CENTRAL : claveSesionActiva;
    String firmaCalculada = calcularFirmaHMACConClave(cuerpo, claveVerificacion);

    if (firmaRx != firmaCalculada) {
        Serial.println("SEC_ALERT|FIRMA_HASH_FALSA|" + String(rssi) + "|Hash ilegal de " + origen + ": " + firmaRx);
        return;
    }

    // 3. Si es la orden CH_SHIFT de la Central, permitir que se ejecute incluso en la segunda ráfaga si aún no saltó
    if (tipo == "CH_SHIFT" && origen == "CENTRAL") {
        String ticketClaro = descifrarPayloadCentralHex(payload, CLAVE_MAESTRA_CENTRAL, nonce);
        int t1 = ticketClaro.indexOf('|');
        int t2 = ticketClaro.indexOf('|', t1 + 1);
        int t3 = ticketClaro.indexOf('|', t2 + 1);

        if (t1 != -1 && t2 != -1 && t3 != -1) {
            int nuevoCanal    = ticketClaro.substring(0, t1).toInt();
            String nuevaClave = ticketClaro.substring(t1 + 1, t2);
            String id1        = ticketClaro.substring(t2 + 1, t3);
            String id2        = ticketClaro.substring(t3 + 1);

            ultimoNonceCentral = nonce;

            // Verificar si nuestro ID está autorizado en este canal seguro
            if (MI_ID == id1 || MI_ID == id2) {
                parAutorizadoEnCanal = true;
                DESTINO_ID = (MI_ID == id1) ? id2 : id1;
                sintonizarCanalFisicoLoRa(nuevoCanal, nuevaClave);
                Serial.println("RX_CH_SHIFT|" + firmaRx + "|" + String(rssi) + "|CH_" + String(nuevoCanal) + "|" + DESTINO_ID);
            } else {
                Serial.println("SEC_ALERT|CANAL_RESTRINGIDO|" + String(rssi) + "|Canal reservado para " + id1 + " y " + id2);
            }
        }
        return;
    }

    // 4. Verificar Anti-Replay por emisor
    if (!verificarYActualizarNonce(origen, nonce)) {
        Serial.println("SEC_ALERT|ATAQUE_REPLAY|" + String(rssi) + "|Nonce clonado de " + origen + ": " + nonce);
        return;
    }

    // 5. Enrutador por ID en la CENTRAL: Si un nodo envía tipo "RELAY" con formato "DESTINO_FINAL:CARGA"
    if (ES_CENTRAL && tipo == "RELAY" && destino == "CENTRAL") {
        int sep = payload.indexOf(':');
        if (sep != -1) {
            String destFinal = payload.substring(0, sep);
            String cargaReal = payload.substring(sep + 1);
            delay(55);
            enviarPaqueteLoRaADestino(destFinal, "MSG", cargaReal);
            Serial.println("SYS_RELAY|" + origen + "->" + destFinal + "|" + firmaRx + "|" + String(rssi));
        }
        return;
    }

    // Si somos la CENTRAL y escuchamos tráfico directo entre NODO_A y NODO_B, lo reportamos al Sniffer
    if (!esParaMi) {
        if (ES_CENTRAL) {
            Serial.println("RX_MONITOR|" + origen + "|" + destino + "|" + tipo + "|" + firmaRx + "|" + String(rssi) + "|" + payload);
        }
        return;
    }

    // --- PAQUETE AUTÉNTICO DIRIGIDO A MI_ID O GLOBAL ("ALL") ---
    if (tipo == "GLOBAL" && origen == "CENTRAL") {
        String mensajeClaro = descifrarPayloadCentralHex(payload, CLAVE_MAESTRA_CENTRAL, nonce);
        for (int i = 0; i < 2; i++) {
            digitalWrite(LED_BUILTIN, HIGH); delay(60);
            digitalWrite(LED_BUILTIN, LOW);  delay(40);
        }
        Serial.println("RX_GLOBAL|" + firmaRx + "|" + String(rssi) + "|" + nonce + "|" + mensajeClaro);
    }
    else if (tipo == "PING") {
        digitalWrite(LED_BUILTIN, HIGH);
        delay(45);
        digitalWrite(LED_BUILTIN, LOW);
        if (destino != "ALL") {
            enviarPaqueteLoRaADestino(origen, "PONG", payload);
        }
        Serial.println("RX_PING|" + firmaRx + "|" + String(rssi) + "|" + payload + "|" + origen);
    }
    else if (tipo == "PONG") {
        Serial.println("RX_PONG|" + firmaRx + "|" + String(rssi) + "|" + payload + "|" + origen);
    }
    else if (tipo == "LED") {
        delay(40);
        if (payload == "ON") {
            digitalWrite(LED_BUILTIN, HIGH);
            if (destino != "ALL") enviarPaqueteLoRaADestino(origen, "LED_ACK", "ON");
            Serial.println("RX_LED|ON|" + firmaRx + "|" + String(rssi) + "|" + origen);
        } else if (payload == "OFF") {
            digitalWrite(LED_BUILTIN, LOW);
            if (destino != "ALL") enviarPaqueteLoRaADestino(origen, "LED_ACK", "OFF");
            Serial.println("RX_LED|OFF|" + firmaRx + "|" + String(rssi) + "|" + origen);
        } else if (payload == "SOS") {
            Serial.println("RX_LED|SOS|" + firmaRx + "|" + String(rssi) + "|" + origen);
            if (destino != "ALL") enviarPaqueteLoRaADestino(origen, "LED_ACK", "SOS");
            ejecutarMorseSOS();
        }
    }
    else if (tipo == "LED_ACK") {
        Serial.println("RX_LED_ACK|" + payload + "|" + firmaRx + "|" + String(rssi) + "|" + origen);
    }
    else if (tipo == "NUDGE") {
        for (int i = 0; i < 4; i++) {
            digitalWrite(LED_BUILTIN, HIGH); delay(50);
            digitalWrite(LED_BUILTIN, LOW);  delay(50);
        }
        Serial.println("RX_NUDGE|" + firmaRx + "|" + String(rssi) + "|" + origen);
    }
    else if (tipo == "MSG") {
        Serial.println("RX_MSG|" + firmaRx + "|" + String(rssi) + "|" + nonce + "|" + payload);
        // Si es un mensaje directo (no broadcast ALL), enviar confirmación de Doble Check (✓✓) al emisor
        if (destino != "ALL") {
            delay(45);
            enviarPaqueteLoRaADestino(origen, "MSG_ACK", firmaRx);
        }
    }
    else if (tipo == "MSG_ACK") {
        Serial.println("RX_MSG_ACK|" + payload + "|" + String(rssi) + "|" + origen);
    }
    else if (tipo == "CALL_REQ" || tipo == "CALL_ACC" || tipo == "CALL_END") {
        Serial.println("RX_" + tipo + "|" + firmaRx + "|" + String(rssi) + "|" + origen);
    }
}

// ============================================================================
// 6. SETUP Y LOOP PRINCIPAL
// ============================================================================
void setup() {
    Serial.begin(115200);

    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);

    pinMode(RFM_SWITCH, OUTPUT);
    digitalWrite(RFM_SWITCH, HIGH);

    #ifdef RFM_SS
    LoRa.setPins(RFM_SS, RFM_RST, RFM_DIO0);
    #else
    LoRa.setPins(SS, RFM_RST, RFM_DIO0);
    #endif

    if (!LoRa.begin(TABLA_FRECUENCIAS[0])) {
        while (1) {
            Serial.println("SYS_ERR|No se pudo iniciar el radio LoRa");
            delay(2000);
        }
    }

    LoRa.setSpreadingFactor(7);
    LoRa.setSignalBandwidth(125E3);
    LoRa.setSyncWord(TABLA_SYNCWORDS[0]);
    LoRa.enableCrc();
    LoRa.receive();
}

void loop() {
    int packetSize = LoRa.parsePacket();
    if (packetSize) {
        String recibido = "";
        while (LoRa.available()) {
            recibido += (char)LoRa.read();
        }
        procesarPaqueteLoRa(recibido, LoRa.packetRssi());
    }

    if (Serial.available()) {
        String linea = Serial.readStringUntil('\n');
        linea.trim();
        if (linea.length() == 0) return;

        if (linea == "CMD_INFO") {
            reportarEstadoSistema();
        }
        // Cambiar el ID del nodo con el que nos comunicamos (NODO_A, NODO_B, CENTRAL o ALL)
        else if (linea.startsWith("CMD_TARGET:")) {
            String nuevoDest = linea.substring(11);
            nuevoDest.trim();
            if (nuevoDest.length() > 0) {
                DESTINO_ID = nuevoDest;
                reportarEstadoSistema();
            }
        }
        // Orden de la CENTRAL para crear clave dinámica y desplazar nodos a un canal seguro
        // Formato: CMD_CH_SHIFT:<numero_canal_0_a_3>:<ID1>,<ID2> (Ej. CMD_CH_SHIFT:1:NODO_A,NODO_B)
        else if (linea.startsWith("CMD_CH_SHIFT:")) {
            String resto = linea.substring(13);
            int sep1 = resto.indexOf(':');
            int sep2 = resto.indexOf(',');
            if (sep1 != -1 && sep2 != -1) {
                int ch = resto.substring(0, sep1).toInt();
                String id1 = resto.substring(sep1 + 1, sep2);
                String id2 = resto.substring(sep2 + 1);
                centralDesplazarNodosACanalSeguro(ch, id1, id2);
            } else {
                int ch = resto.toInt();
                centralDesplazarNodosACanalSeguro(ch, "NODO_A", "NODO_B");
            }
        }
        // Difusión global cifrada desde la CENTRAL hacia ambos nodos simultáneamente
        else if (linea.startsWith("CMD_GLOBAL:")) {
            centralEnviarMensajeGlobal(linea.substring(11));
        }
        // Enviar mensaje a un ID específico a través de la CENTRAL como intermediaria
        else if (linea.startsWith("CMD_VIA_CENTRAL:")) {
            enviarPaqueteLoRaADestino("CENTRAL", "RELAY", DESTINO_ID + ":" + linea.substring(16));
        }
        else if (linea.startsWith("CMD_MSG:")) {
            enviarPaqueteLoRa("MSG", linea.substring(8));
        }
        else if (linea.startsWith("CMD_PING:")) {
            enviarPaqueteLoRa("PING", linea.substring(9));
        }
        else if (linea == "CMD_LED:ON") {
            enviarPaqueteLoRa("LED", "ON");
        }
        else if (linea == "CMD_LED:OFF") {
            enviarPaqueteLoRa("LED", "OFF");
        }
        else if (linea == "CMD_LED:SOS") {
            enviarPaqueteLoRa("LED", "SOS");
        }
        else if (linea == "CMD_NUDGE") {
            enviarPaqueteLoRa("NUDGE", "ZUMBIDO");
        }
        else if (linea == "CMD_CALL:REQ") {
            enviarPaqueteLoRa("CALL_REQ", "RING");
        }
        else if (linea == "CMD_CALL:ACC") {
            enviarPaqueteLoRa("CALL_ACC", "OK");
        }
        else if (linea == "CMD_CALL:END") {
            enviarPaqueteLoRa("CALL_END", "BYE");
        }
        // --- COMANDOS DEL SIMULADOR DE ATAQUES EN VIVO ---
        else if (linea == "CMD_ATK:FAKE_HASH") {
            String tramaFalsa = MI_ID + "|" + DESTINO_ID + "|9999|LED|ON|deadbeefcafebabe";
            transmitirCrudoLoRa(tramaFalsa);
            Serial.println("SYS_ATK_SENT|FIRMA_HASH_FALSA|" + tramaFalsa);
        }
        else if (linea == "CMD_ATK:SPOOF") {
            String tramaIntruso = "HACKER_X|" + DESTINO_ID + "|8888|MSG|Hack|1122334455667788";
            transmitirCrudoLoRa(tramaIntruso);
            Serial.println("SYS_ATK_SENT|INTRUSO_EXTERNO|" + tramaIntruso);
        }
        else if (linea == "CMD_ATK:REPLAY") {
            if (ultimoPaqueteValidoEnviado.length() == 0) {
                enviarPaqueteLoRa("PING", "SEED");
                delay(80);
            }
            transmitirCrudoLoRa(ultimoPaqueteValidoEnviado);
            Serial.println("SYS_ATK_SENT|ATAQUE_REPLAY|" + ultimoPaqueteValidoEnviado);
        }
    }
}
