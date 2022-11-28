package com.brunomilitzer.demo.student;

public record Student(Long studentId, String studentName) {

    @Override
    public String toString() {
        return "Student {" +
                "studentId=" + studentId +
                ", studentName'" + studentName + '\'' +
                "}";
    }

}
