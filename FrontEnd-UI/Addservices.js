import React, { Component } from 'react';

// import { BrowserRouter, Route } from 'react-router-dom';
// import Monitoring from './Monitoring.js';

import { Button, FormGroup, FormControl, controlId,Form,FormLabel} from "react-bootstrap";
import { useState } from 'react'
import { BrowserRouter, Redirect, Route } from 'react-router-dom'
import { connect } from 'react-redux'
import PropTypes from 'prop-types'
import { serviceadd } from '../actions/authAction'
import Alert from '../layout/Alert'

import Navigation from './Navigation'
import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'

// import { Prev } from 'react-bootstrap/PageItem';
import axios from 'axios';
import './Addservices.css';

const Addservices =({serviceadd, isAuthenticated,auth,role,token })=>{
  
const [formData, setFormData] = useState({
IPaddress: '',
account: '',
password: '',
service: '',
status: false
});

const{ IPaddress, account, password, service,status} = formData;


// const onChange = e =>
//     setFormData({ ...formData, [e.target.name]: e.target.value })

  // const onSubmit = async e => {
  //   e.preventDefault()

  //   serviceadd({  IPaddress, account, passsword, service });
  //   console.log(formData)
  //   console.log(IPaddress, account, passsword, service)
  // }; 


// class Department extends Component {
  //constructor(props) {
  //  super(props);

    // this.state = {
    //  IPaddress: "",
    //   account: "",
    //   password:"",
    //   service: "",
    //   status:false
    // };
    
  

  // validateForm() 
  //   return this.state.IPaddress.length > 0 && this.state.account.length > 0 && this.state.password.length>0;
  

  const handleChange = e => {
    setFormData({ ...formData, [e.target.name]: e.target.value })

    // this.setState(
    //   {[name]: e.target.value}
    // )
   //this.setState({name: event.target.value});
    //console.log(this.state, name);
    // this.setState({
    //   [event.target.id]: event.target.value
    // });
  }

  const updateStatus =(response) =>{
    setFormData({status:response});


  }

  const handleSubmit = (e) => {
    e.preventDefault();
  
    serviceadd(formData)
   
    
    setFormData({status:null});


    axios(
      {
      method: "post",
      url:"http://192.168.1.110:8080/execute-VM",
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
        
{/* <Tab></Tab> */}

            <div className='col s12 m8 l9  offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
              {/* <!-- Note that "m8 l9" was added --> */}
              {/* <!-- Teal page content */}

              <div className="Login white">
     <h1 className="center black-text">Add VM's</h1>
           <br />
     <form onSubmit={e => handleSubmit(e)}>
       <FormGroup controlId="IPaddress " >
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
          <FormGroup controlId="exampleForm.ControlSelect1" >
    <FormLabel className="black-text">Select Service</FormLabel>
    <FormControl as="select" name="service" onChange={(e)=>handleChange(e)} 
    value={service}
 
    >
    
   
      <option value="" disabled selected>Choose your Services</option>
      <option >HTTP</option>
      <option >SSH</option>
      <option >MYSQL</option>
    
    
 
    </FormControl>
  </FormGroup>
          <Button
           className="btn btn-danger black-text"
            block
            
           // disabled={!this.validateForm()}
            type="submit"
            onSubmit={(e)=>handleSubmit(e)}
            
          >
            Add VM
          </Button>
          <div>
            <br></br>
            <br></br>
<h3 className="center black-text"  style={{ borderTop: "solid",paddingTop:"10px"}}>Status</h3>
<br></br>

<div >
  {status == false ? null : status  ?

  <div className="led-box" style={{marginLeft:'37%'}}>
    <div className="led-green" > </div>
    <p>Running </p>
    
  </div>
  :
  <div className="led-box" style={{marginLeft:'37%'}}>
    <div className="led-red"></div>
    <p>Not Running </p>
  </div>
 

  }
</div>

</div>
        </form>
      </div>

      </div>
            </div>
          </div>
       
      </BrowserRouter>
       
    )}
   

    Addservices.propTypes = {
      serviceadd: PropTypes.func.isRequired,
      isAuthenticated: PropTypes.bool,
    };
    
    const mapStateToProps = state => ({
      isAuthenticated: state.auth.isAuthenticated,
      token: state.auth.token,
      role: state.auth.role
    })
    
    export default connect(mapStateToProps, { serviceadd })(Addservices)
