import React, { Component } from 'react';
// import './UserManagement.css';
import './Addrole.css';
// import LineChart from './LineChart';
// import BarChart from './BarChart';
import { BrowserRouter, Route } from 'react-router-dom';
// import Monitoring from './Monitoring.js';
// import Configuration from './Configuration.js';
// import Signup from './Signup.js';
// import Dashboard from './Dashboard';
// import Monitoring from './Monitoring.js';
// import Updaterole from './Updaterole';
// import Deleterole from './Deleterole';
// import UserManagement from './UserManagement';
import { Button, FormGroup, FormControl } from "react-bootstrap";
import Navigation from './Navigation'
// import dashboard from './dashboard.js';
// import Logs from './Logs.js';
import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
class Deleterole extends Component {
  constructor(props) {
    super(props);

    this.state = {
     username: "",
      email: "",
      role:""
    };
  }

  validateForm() {
    return this.state.email.length > 0 && this.state.username.length > 0 && this.state.role.length>0;
  }

  handleChange = event => {
    this.setState({
      [event.target.id]: event.target.value
    });
  }

  handleSubmit = event => {
    event.preventDefault();
  }

  render() {
    return (
      <BrowserRouter>
            <Route path='/navigation' component={Navigation} />
        <div className='app'>
        {this.props.role === "admin" ? <Navigation/>:(this.props.role === "manager" ? <NavigationManager/>:(this.props.role === "submanager"?<NavigationSubManager/>:null ) )}
          {/* <!-- Navbar goes here --> */}
          

          <div className='row'>
            

            <div className='col s12 m8 l9  offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
              {/* <!-- Note that "m8 l9" was added --> */}
              {/* <!-- Teal page content */}

              <div className="Login white">
     <h1 className="center black-text">Add role</h1>
           <br />
     <form onSubmit={this.handleSubmit}>
       <FormGroup controlId="email" bsSize="large">
         <controlId className="black-text">username</controlId>
      <FormControl
              autoFocus
              type="text"
              value={this.state.username}
              onChange={this.handleChange}
            />
          </FormGroup>
          <FormGroup controlId="email" bsSize="large">
            <controlId className="black-text">Email</controlId>
            <FormControl
            className="black-text"
              value={this.state.email}
              onChange={this.handleChange}
              type="email"
            />
          </FormGroup>
          <FormGroup controlId="email" bsSize="large">
            <controlId className="black-text">Role</controlId>
            <FormControl
            className="black-text"
              value={this.state.role}
              onChange={this.handleChange}
              type="text"
            />
          </FormGroup>
          <Button
           className="btn btn-danger black-text"
            block
            bsSize="small"
            disabled={!this.validateForm()}
            type="submit"
            
          >
            Delete 
          </Button>
        </form>
      </div></div>
            </div>
          </div>
       
      </BrowserRouter>
       
    );
   }
}
export default Deleterole;
