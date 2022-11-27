package com.brunomilitzer.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student( 1L, "Vanessa de Garcez" ),
            new Student( 2L, "Tales Coelho" ),
            new Student( 3L, "Bruno Bruno" )
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent( @PathVariable("studentId") final Long studentId ) {
        return STUDENTS.stream().filter( student -> studentId.equals( student.studentId() ) )
                .findFirst().orElseThrow(() -> new IllegalStateException("Student " + studentId + " Not Found"));
    }

}
