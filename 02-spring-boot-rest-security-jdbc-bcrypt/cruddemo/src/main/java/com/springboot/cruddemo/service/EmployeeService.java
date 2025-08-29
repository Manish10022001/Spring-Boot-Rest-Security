package com.springboot.cruddemo.service;
//step :5
import com.springboot.cruddemo.entity.Employee;

import java.util.List;

public interface EmployeeService {
    List<Employee> findAll();

    //Step 9: add methods
    Employee findById(int theId);
    Employee save(Employee theEmployee);
    void deleteById(int theId);
}
