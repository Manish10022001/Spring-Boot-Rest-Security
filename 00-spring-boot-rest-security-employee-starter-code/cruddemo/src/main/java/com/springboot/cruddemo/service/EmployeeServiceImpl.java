package com.springboot.cruddemo.service;
//Step 6

import com.springboot.cruddemo.dao.EmployeeRepository;
import com.springboot.cruddemo.entity.Employee;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class EmployeeServiceImpl implements EmployeeService {
    //define field to add reference to EmployeeDAO
    private EmployeeRepository employeeRepository;

    //Inject EmployeeDAO
    @Autowired
    public EmployeeServiceImpl(EmployeeRepository theEmployeeRepository){
        employeeRepository = theEmployeeRepository;
    }
    @Override
    public List<Employee> findAll(){
        return employeeRepository.findAll();
    }

    @Override
    public Employee findById(int theId){
        //Call the repository method to find employee by ID.
        // findById returns Optional<Employee> — a container that may or may not contain an Employee object.
        Optional<Employee> result = employeeRepository.findById(theId);
        //Create a reference variable to hold the employee if found
        Employee theEmployee = null;

        //Check if the Optional contains a value (i.e., employee exists)
        if (result.isPresent()) {
            //If present, get the actual Employee from the Optional
            theEmployee = result.get();
        } else {
            // If not present, it means the employee with the given ID was not found
            // So we throw a RuntimeException to inform the caller
            throw new RuntimeException("Did not find employee ID - " + theId);
        }
        return theEmployee;
    }
    @Override
    public Employee save(Employee theEmployee){
        return employeeRepository.save(theEmployee);
    }

    @Override
    public void deleteById(int theId){
        employeeRepository.deleteById(theId);
    }
}
