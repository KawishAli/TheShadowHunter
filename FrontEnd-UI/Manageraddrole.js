
import React, { useState, Component } from 'react'
import { BrowserRouter, Redirect, Route } from 'react-router-dom'
import { connect } from 'react-redux'
import PropTypes from 'prop-types'
import {managerregister } from '../actions/managerAuthAction'
import Alert from '../layout/Alert'
import addservices from './Addservices';



import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'

import { Button, FormGroup, FormControl } from "react-bootstrap";
import Navigation from './Navigation'
import './Addrole.css';



// class Addrole extends Component {
//   constructor(props) {
//     super(props);

//     this.state = {
//      username: "",
//       email: "",
//       role:""
//     };
    const Manageraddrole = ({ managerregister, isAuthenticated,auth,roles,token }) => {
      const [formData, setFormData] = useState({
        username: '',
        email: '',
        role: 'Manager'
      });
  
  const { username, email, role } = formData;

  const onChange = e =>
    setFormData({ ...formData, [e.target.name]: e.target.value })

  const onSubmit = async e => {
    e.preventDefault()

    managerregister({ username, email, role });
  };

  // //Redirect if logged  in 
  //  if (isAuthenticated) {
  //  return <Redirect to='/dashboard' />
  //  }

  
   

  // handleChange = event => {
  //   this.setState({
  //     [event.target.id]: event.target.value
  //   });
  // }

  // handleSubmit = event => {
  //   event.preventDefault();
  // }

  // render() {
    return (
      <BrowserRouter>
   <Route path='/navigation' component={Navigation} />
        <div className='app'>
        {roles === "admin" ? <Navigation/>:(roles === "manager" ? <NavigationManager/>:(roles === "submanager"?<NavigationSubManager/>:null ) )}
          {/* <!-- Navbar goes here --> */}
          

          <div className='row'>
            

            <div className='col s12 m8 l9  offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
              {/* <!-- Note that "m8 l9" was added --> */}
              {/* <!-- Teal page content */}

              <div className="Login white">
     <h1 className="center black-text">Add role</h1>
           <br />
           <form onSubmit={e => onSubmit(e)}>
       <FormGroup controlId="username" bsSize="large">
         <controlId className="black-text">username</controlId>
         <Alert />
      <FormControl
              // autoFocus
              // type="text"
              // value={this.state.username}
              // onChange={this.handleChange}
              type="text"
              className="form-control black-text "
              name="username"
              placeholder="Username "
              value={username}
              onChange={e => onChange(e)}
              required

            />
          </FormGroup>
          <FormGroup controlId="email" bsSize="large">
            <controlId className="black-text">Email</controlId>
            <FormControl
            // className="black-text"
            //   value={this.state.email}
            //   onChange={this.handleChange}
            //   type="email"
            type="email"
                      className="form-control black-text "
                      name="email"
                      placeholder="Email Address"
                      value={email}
                      onChange={e => onChange(e)}
                      required
            />
          </FormGroup>
          <FormGroup controlId="role" bsSize="large">
            <controlId className="black-text">Role</controlId>
            <FormControl
            // className="black-text"
            //   value={this.state.role}
            //   onChange={this.handleChange}
            //   type="text"
            type="text"
            className="form-control black-text "
            name="role"
            placeholder="role"
            value={role}
            // onChange={e => onChange(e)}
            required
            />
          </FormGroup>
          <Button
           className="btn btn-danger black-text"
            block
            bsSize="small"
            //disabled={!this.validateForm()}
            type="submit"
            
          >
            Add 
          </Button>
        </form>

      </div>
      </div>
            </div>
          </div>
       
      </BrowserRouter>
        
    )
    }
    Manageraddrole.propTypes = {
      register: PropTypes.func.isRequired,
      isAuthenticated: PropTypes.bool,
    };
    
    const mapStateToProps = state => ({
      isAuthenticated: state.auth.isAuthenticated,
      token: state.auth.token,
      roles: state.auth.role
    })
    
    export default connect(mapStateToProps, {managerregister  })(Manageraddrole)
    
