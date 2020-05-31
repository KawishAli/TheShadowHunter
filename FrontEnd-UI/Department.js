import React, { Component } from 'react';

import './Addrole.css';
import LineChart from './LineChart';
import BarChart from './BarChart';
import { BrowserRouter, Route } from 'react-router-dom';
// import Monitoring from './Monitoring.js';
import AddedVM from './AddedVM.js';
import Signup from './Signup.js';
import Dashboard from './Dashboard';
import Monitoring from './Monitoring.js';
import Updaterole from './Updaterole';
import Deleterole from './Deleterole';
import Roles from './Roles';
import PropTypes from 'prop-types'
import {connect} from 'react-redux'
import { departmentadd } from '../actions/authAction'
import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
import { useState } from 'react'
import { Button, FormGroup, FormControl, controlId } from "react-bootstrap";
import Navigation from './Navigation'
// import dashboard from './dashboard.js';
import Logs from './Logs.js';
import axios from 'axios';
import Alert from '../layout/Alert'

const Department =({departmentadd, isAuthenticated,auth,role,token })=>{
  
  const [formData, setFormData] = useState({
  IPaddress: '',
  account: '',
  password: '',
 
  status: false
  })
  
  const{ IPaddress, account, password,status} = formData;


  const handleChange = e => {
    setFormData({ ...formData, [e.target.name]: e.target.value })
  }

  const updateStatus =(response) =>{
    setFormData({status:response});


  }

  const handleSubmit = (e) => {
    e.preventDefault();
  
    departmentadd(formData)
   
    
    setFormData({status:null});


    axios(
      {
      method: "post",
      url:"http://182.180.130.115:8080/add-department",
      data: {"User_data":(formData)}
    }
    ).then(res=>{
      console.log(res.data);
       updateStatus(res.data);
    
    }).catch(err=>{console.log(err)})
    console.log(JSON.stringify(formData))
    
 
  }



  
    return (
      <BrowserRouter>
            <Route path='/navigation' component={Navigation} />
        <div className='app'>
        {role === "admin" ? <Navigation/>:(role === "manager" ? <NavigationManager/>:(role === "submanager"?<NavigationSubManager/>:null ) )}
          {/* <!-- Navbar goes here --> */}
          

          <div className='row'>
            

          <div className='col s12 m8 l9  offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
              {/* <!-- Note that "m8 l9" was added --> */}
              {/* <!-- Teal page content */}

              <div className="Login white">
     <h1 className="center black-text">Add Department</h1>
           <br />
     <form onSubmit={e => handleSubmit(e)}>
       <FormGroup controlId="IPaddress" bsSize="large">
       <p className="black-text">IP address</p>
         <Alert />
      <FormControl
            type="text"
            className="form-control black-text "
            name="IPaddress"
            placeholder="IPaddress "
            value={IPaddress}
            // value={this.state.IPaddress.name || ''} 
            // onChange={e => onChange(e)}
            onChange={e => handleChange (e)}
            required
            />
          </FormGroup>
          <FormGroup controlId="account">
            <p className="black-text">Account</p>
            <FormControl
        placeholder="account"
            className="black-text"
            name = "account"
              value={account}
              // value={this.state.account.name || ''} 
              onChange={e => handleChange(e)}
              
              type="text"
            />
          </FormGroup>
          <FormGroup controlId="Password" >
            <p className="black-text">Password</p>
            <FormControl
            type="password"
            className="form-control black-text "
            name="password"
            placeholder="password "
            value={password}
            // value={this.state.password.name || ''} 
            // onChange={e => onChange(e)}
            onChange={e => handleChange(e)}
            required
            />
          </FormGroup>
          <Button
          className="btn btn-danger black-text"
          block
          bsSize="small"
            // disabled={validateForm()}
            type="submit"
            onSubmit={(e)=>handleSubmit(e)}
            
          >
            Add Department
          </Button>
          <br></br>

          {/* <a href="/viewdepartments" class="btn waves-effect white waves-light" type="submit" name="action">Add
</a> */}
           <Button
           className="waves-effect waves-light btn"
            block
            bsSize="small"
            // disabled={validateForm()}
            type="submit"
          href={role === "admin" ?'/monitoring':(role === "manager" ? '/managermonitoring':null ) }
            
          >
            View Department
          </Button>
          
          <div>
            <br></br>
            <br></br>
<h3 className="center black-text"  style={{ borderTop: "solid",paddingTop:"10px"}}>Status</h3>
<br></br>

<div >
  {status == false? null :
  status ?

  <div className="led-box" style={{marginLeft:'37%'}}>
    <div className="led-green" > </div>
    <p>Department Added </p>
    
  </div>
  :
  <div className="led-box" style={{marginLeft:'37%'}}>
  <div className="led-yellow"></div>
  <p>Department Adding</p>
</div>
    

  }
</div>


</div>

        </form>




   











      </div></div>
            </div>
          </div>
       
      </BrowserRouter>
       
    );
   }

Department.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps, { departmentadd })(Department)

