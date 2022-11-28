package com.brunomilitzer.demo.student;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student( 1L, "Vanessa de Garcez" ),
            new Student( 2L, "Tales Coelho" ),
            new Student( 3L, "Bruno Bruno" )
    );

    @GetMapping
    public List<Student> getAllStudents() {
        System.out.println("getAllStudents");
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent( @RequestBody final Student student ) {
        System.out.println("registerNewStudent");
        System.out.println( student );
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent( @PathVariable("studentId") final Long studentId ) {
        System.out.println("deleteStudent");
        System.out.println( studentId );
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent( @PathVariable("studentId") final Long studentId, @RequestBody final Student student ) {
        System.out.println("updateStudent");
        System.out.printf( "%s %s%n", studentId, student );
    }

}
