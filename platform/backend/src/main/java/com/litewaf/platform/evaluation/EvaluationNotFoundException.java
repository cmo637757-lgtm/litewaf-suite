package com.litewaf.platform.evaluation;

/** 评估跑次不存在。单独一个异常类，是为了让全局处理器能精确映射成 404。 */
public class EvaluationNotFoundException extends RuntimeException {

    public EvaluationNotFoundException(String message) {
        super(message);
    }
}
