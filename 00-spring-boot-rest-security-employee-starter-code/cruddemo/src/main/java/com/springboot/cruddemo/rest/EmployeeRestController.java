package com.springboot.cruddemo.rest;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.springboot.cruddemo.entity.Employee;
import com.springboot.cruddemo.service.EmployeeService;

import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

//step 4: create rest controller to use DAO
@RestController
@RequestMapping("/")
public class EmployeeRestController {

    //define field to add reference to EmployeeService
    private EmployeeService employeeService;
    private ObjectMapper objectMapper; //step 12.1: for object mapper

    //Inject Constructor                           step 12.2 : add new entry for object mapper
    public EmployeeRestController(EmployeeService theEmployeeService, ObjectMapper theObjectMapper){
        employeeService = theEmployeeService;
        objectMapper = theObjectMapper;
    }

    //expose "/employees" and return list of all employees
    @GetMapping("/employees")
    public List<Employee> findAll(){
        return employeeService.findAll();
    }

    //step 11
    //Read a single employee
    @GetMapping("/employees/{employeeId}")
    public Employee getEmployeeById(@PathVariable int employeeId){
        Employee theEmployee = employeeService.findById(employeeId);
        if(theEmployee == null){
            throw new RuntimeException("Employee id not found - "+employeeId);
        }
        return theEmployee;
    }
    //Add mapping for POST /employees - add new employee
    @PostMapping("/employees")
    //as we pass data as json we use @RequestBody, it is used to bind the json
    public Employee save(@RequestBody Employee theEmployee){
        //also just in case they pass an id in json.... set id to 0
        //this is to force a save of new item ... instead of update
        theEmployee.setId(0);

        Employee dbEmployee = employeeService.save(theEmployee);

        return dbEmployee;
    }

    //add mapping for PUT /employees - update existing employees
    @PutMapping("/employees")
    public Employee updateEmployee(@RequestBody Employee theEmployee){
        Employee dbEmployee = employeeService.save(theEmployee);
        return dbEmployee;
    }

    //step 12.3: add support for @PatchMapping request
    //add patch mapping for PATCH /employees/{employeeId} -- patch employee ... partial
    @PatchMapping("/employees/{employeeId}")
    public Employee patchEmployee(@PathVariable int employeeId,
                                  @RequestBody Map<String,Object> patchPayLoad){
        Employee tempEmployee = employeeService.findById(employeeId);

        //throw exception if null
        if(tempEmployee == null){
            throw new RuntimeException("Employee id not found - "+employeeId);
        }

        //Throw exception if request body contains "id" key
        if(patchPayLoad.containsKey("id")){
            throw new RuntimeException ("Employee id not allowed in request body - "+employeeId);
        }

        Employee patchEmployee = apply(patchPayLoad, tempEmployee);

        //step 12.5: apply method to update value and return it
        Employee dbEmployee = employeeService.save(patchEmployee);
        return dbEmployee;
    }
    //step 12.4 apply method
    private Employee apply(Map<String,Object>patchPayLoad, Employee tempEmployee){
        //convert employee object to a JSON object node
        ObjectNode employeeNode = objectMapper.convertValue(tempEmployee, ObjectNode.class);
        //convert the patchPayLoad map to a JSON object node
        ObjectNode patchNode = objectMapper.convertValue(patchPayLoad, ObjectNode.class);

        //Merge the patch updates into the employee node
        employeeNode.setAll(patchNode);

        return objectMapper.convertValue(employeeNode, Employee.class);
    } //step 12 for patch mapping over

    //add mapping for DELETE /employees/{employeeId} - delete employee
    @DeleteMapping("/employees/{employeeId}")
    public String deleteEmployee(@PathVariable int employeeId){
        Employee tempEmployee = employeeService.findById(employeeId);

        //throw exception if null
        if(tempEmployee == null){
            throw new RuntimeException("Employee id not found - "+employeeId);
        }
        employeeService.deleteById(employeeId);
        return "Deleted employee id - "+employeeId;
    }

}
