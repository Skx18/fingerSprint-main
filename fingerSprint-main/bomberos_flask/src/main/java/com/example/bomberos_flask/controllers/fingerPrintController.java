package com.example.bomberos_flask.controllers;

import com.digitalpersona.uareu.*; // Importa las clases del SDK
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.example.bomberos_flask.controllers.FingerprintVerificationRequest.UserFingerprint;

@RestController
@RequestMapping("/fingerprint")
public class fingerPrintController {
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> registerFingerprint(@RequestBody Map<String, Object> userData) {
        try {
            // Inicializar el dispositivo
            ReaderCollection readers = UareUGlobal.GetReaderCollection();
            readers.GetReaders();

            if (readers.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "No se encontró ningún lector de huellas."));
            }

            Reader reader = readers.get(0);
            reader.Open(Reader.Priority.EXCLUSIVE);

            // Capturar la imagen de la huella
            Reader.CaptureResult result = reader.Capture(
                    Fid.Format.ANSI_381_2004,
                    Reader.ImageProcessing.IMG_PROC_DEFAULT,
                    500,
                    5000 // Timeout de captura
            );

            reader.Close();

            if (result == null || result.image == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "No se pudo capturar la huella digital."));
            }

            // Convertir la imagen en un objeto FMD
            Engine engine = UareUGlobal.GetEngine();
            Fmd fmd = engine.CreateFmd(result.image, Fmd.Format.ANSI_378_2004);

            // Obtener los bytes del FMD y codificarlos en Base64
            byte[] fmdBytes = fmd.getData();
            String fmdBase64 = Base64.getEncoder().encodeToString(fmdBytes);

            // Agregar la huella al mapa recibido
            userData.put("huella", fmdBase64);

            // Realizar el POST a la URL externa para crear el usuario
            String url = "https://bomberos-flask.onrender.com/users/";

            // Preparamos los headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            // Creamos el objeto de solicitud
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(userData, headers);

            // Enviamos la solicitud POST
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

            // Retornamos la respuesta de la API externa
            if (response.getStatusCode() == HttpStatus.CREATED) {
                return ResponseEntity.ok(Map.of("message", "Usuario creado exitosamente", "data", response.getBody()));
            } else {
                return ResponseEntity.status(response.getStatusCode()).body(Map.of("error", "No se pudo crear el usuario en la API externa"));
            }

        } catch (UareUException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al registrar la huella: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error inesperado: " + e.getMessage()));
        }
    }

    public List<FingerprintVerificationRequest.UserFingerprint> getStoredFingerprintsFromFlask() {
        String flaskUrl = "http://localhost:5000/fingerPrint"; // Asegúrate de que Flask esté corriendo en este puerto
        RestTemplate restTemplate = new RestTemplate();

        try {
            // Realiza la solicitud GET a Flask
            ResponseEntity<FingerprintVerificationRequest.UserFingerprint[]> response = restTemplate.exchange(flaskUrl,
                    HttpMethod.POST, null, FingerprintVerificationRequest.UserFingerprint[].class);

            // Verifica si la respuesta es válida
            if (response.getBody() != null) {
                return Arrays.asList(response.getBody());
            } else {
                return List.of();
            }
        } catch (Exception e) {
            System.err.println("Error obteniendo huellas de Flask: " + e.getMessage());
            return List.of(); // Retorna lista vacía en caso de error
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyFingerprint(
            @RequestBody List<FingerprintVerificationRequest.UserFingerprint> users) {
        try {
            // Inicializar lector de huellas
            ReaderCollection readers = UareUGlobal.GetReaderCollection();
            readers.GetReaders();

            if (readers.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("message", "No se encontró ningún lector de huellas."));
            }

            Reader reader = readers.get(0);
            reader.Open(Reader.Priority.EXCLUSIVE);

            // Capturar la huella digital
            Reader.CaptureResult result = reader.Capture(
                    Fid.Format.ANSI_381_2004,
                    Reader.ImageProcessing.IMG_PROC_DEFAULT,
                    500,
                    5000 // Timeout
            );

            reader.Close();

            if (result == null || result.image == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("message", "No se pudo capturar la huella digital."));
            }

            // Convertir la imagen en un FMD
            Engine engine = UareUGlobal.GetEngine();
            Fmd capturedFmd = engine.CreateFmd(result.image, Fmd.Format.ANSI_378_2004);

            // Convertir las huellas almacenadas en FMD
            int bestScore = Integer.MAX_VALUE;
            Long bestMatchId = null;

            for (FingerprintVerificationRequest.UserFingerprint user : users) {
                System.out.println("Encoded String: " + user.getFingerPrint());

                byte[] storedData = Base64.getDecoder().decode(user.getFingerPrint());
                Fmd storedFmd = UareUGlobal.GetImporter().ImportFmd(storedData, Fmd.Format.ANSI_378_2004,
                        Fmd.Format.ANSI_378_2004);

                // Comparar con la huella capturada
                int score = engine.Compare(capturedFmd, 0, storedFmd, 0);

                if (score < bestScore) { // Menor score = mejor coincidencia
                    bestScore = score;
                    bestMatchId = user.getId();
                }
            }

            if (bestMatchId == null || bestScore >= 2000) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Huella no reconocida"));
            }

            // Enviar respuesta con el ID del usuario que más coincidió
            Map<String, Object> response = new HashMap<>();
            response.put("id", bestMatchId);
            response.put("score", bestScore);

            return ResponseEntity.ok(response);

        } catch (UareUException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error en la verificación: " + e.getMessage()));
        }
    }
}