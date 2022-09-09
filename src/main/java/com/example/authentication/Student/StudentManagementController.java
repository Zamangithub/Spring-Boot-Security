package com.example.authentication.Student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/student")
public class StudentManagementController  {


        private static final List<Student> STUDENTS = Arrays.asList(
                new Student(1,"Gul"),
                new Student(2,"shahZaib"),
                new Student(3,"Azan")
        );
        @GetMapping
        @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
        public List<Student> getAllStudent(){
            return STUDENTS;
        }

        @PostMapping
       @PreAuthorize("hasAuthority('student:write')")
        public void registerNewStudent(@RequestBody Student student){
                System.out.println("registerNewStudent");
                System.out.println(student);
        }

        @DeleteMapping(path = "{studentId}")
        @PreAuthorize("hasAuthority('student:write')")
        public void deleteStudent(@PathVariable("studentId") Integer studentId){
                System.out.println("Delete Student");
                System.out.println(studentId);
        }

        @PutMapping(path ="{studentId}")
        @PreAuthorize("hasAuthority('student:write')")
        public void updateStudent(@PathVariable("studentId") Integer studentId ,@RequestBody Student student){
                System.out.println("Update Student");
                System.out.println(String.format("%s %s",studentId,student ));
        }
}
