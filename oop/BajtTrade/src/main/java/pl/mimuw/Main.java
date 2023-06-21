package pl.mimuw;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.*;
import java.nio.file.Paths;
import java.util.Random;

public class Main {
    public static final Random random = new Random();

    public static void main(String[] args) {
        if (!czyPoprawneWejscie(args)) {
            System.out.println("Niepoprawne wejście!");
            return;
        }

        // Szukanie całkowitej ścieżki do pliku wejściowego, żeby działał na każdym urządzeniu.
        String absoluteInputPath = new File(args[0]).getAbsolutePath();
        String absoluteOutputPath = new File(args[1]).getAbsolutePath();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        // Wczytywanie wejścia.
        try {
            BajtTrade bajtTrade = objectMapper.readValue(Paths.get(absoluteInputPath).toFile(), BajtTrade.class);
            // Wywołanie symulacji.
            bajtTrade.wykonajSymulacje();
            objectMapper.writeValue(new File(absoluteOutputPath), bajtTrade);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean czyPoprawneWejscie(String[] args) {
        return args.length == 2;
    }
}
