package ch.zhaw.securitylab.marketplace.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class CreditCardValidator implements ConstraintValidator<CreditCardCheck, String> {

    @Override
    public void initialize(CreditCardCheck constraintAnnotation) {}

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) {
            return false;
        }
        String digits = value.replaceAll("\\D", ""); // remove non-digits
        return checkRawFormat(value) && luhnCheck(digits);
    }

    private boolean checkRawFormat(String cardNumber) {
        return cardNumber.matches("^\\d{4}[ ]?\\d{4}[ ]?\\d{4}[ ]?\\d{4}$");
    }

    private boolean luhnCheck(String cardDigits) {
        int sum = 0;

        for (int i = cardDigits.length() - 1; i >= 0; i -= 2) {
            sum += Integer.parseInt(cardDigits.substring(i, i + 1));
            if (i > 0) {
                int d = 2 * Integer.parseInt(cardDigits.substring(i - 1, i));
                if (d > 9) {
                    d -= 9;
                }
                sum += d;
            }
        }
        return sum % 10 == 0;
    }
}