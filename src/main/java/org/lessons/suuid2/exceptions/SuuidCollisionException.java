package org.lessons.suuid2.exceptions;

public class SuuidCollisionException extends RuntimeException {
    public SuuidCollisionException(String message) {
        super(message);
    }
}
