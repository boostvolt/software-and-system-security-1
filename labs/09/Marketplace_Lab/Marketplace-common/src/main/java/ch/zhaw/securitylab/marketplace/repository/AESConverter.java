package ch.zhaw.securitylab.marketplace.repository;

import java.util.Base64;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import ch.zhaw.securitylab.marketplace.service.AESCipherService;

@Converter
public class AESConverter implements AttributeConverter<String, String> {

    private final AESCipherService aesCipherService;

    public AESConverter(AESCipherService aesCipherService) {
        this.aesCipherService = aesCipherService;
    }

    @Override
    public String convertToDatabaseColumn(String plainTextData) {
        byte[] encryptedData = aesCipherService.encrypt(plainTextData.getBytes());
        return new String(Base64.getEncoder().encode(encryptedData));
    }

    @Override
    public String convertToEntityAttribute(String cipherTextData) {
        byte[] encryptedData = Base64.getDecoder().decode(cipherTextData);
        return new String(aesCipherService.decrypt(encryptedData));
    }
}