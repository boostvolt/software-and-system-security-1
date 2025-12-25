package ch.zhaw.securitylab.marketplace.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({METHOD, FIELD})
@Retention(RUNTIME)
@Documented
@Constraint(validatedBy = CreditCardValidator.class)
public @interface CreditCardCheck {

    String message() default "Please insert a valid credit card number (16 digits).";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}