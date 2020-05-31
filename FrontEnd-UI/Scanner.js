import React, { Component } from 'react';
// import './UserManagement.css';
import './Scanner.css';
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
import PropTypes from 'prop-types'
import {connect} from 'react-redux'

import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
// import dashboard from './dashboard.js';
import axios from 'axios';

class Scanner extends Component{

    constructor(props) {
        super(props);
    
        this.state = {
         IPaddress: "",
          status:false,
          scanner: null
        }
       
        
      }
    
      validateForm() {
        return this.state.IPaddress.length > 0;
      }
    
      handleChange = (event, name) => {
        
        this.setState(
          {[name]: event.target.value}
        )
       //this.setState({name: event.target.value});
        //console.log(this.state, name);
        // this.setState({
        //   [event.target.id]: event.target.value
        // });
      }
    
      updateStatus =(response) =>{
        this.setState({status:response});
    
    
      }
    
      handleSubmit = (event) => {
        event.preventDefault();
        this.setState({status:null});
    
        axios(
          {
          method: "post",
          url:"http://192.168.1.110:8080/execute-scanner",
          data: {"User_data":(this.state)}
        }
        ).then(res=>{
          console.log(res.data);
           this.updateStatus(res.data);
        
        }).catch(err=>{console.log(err)})
        console.log(JSON.stringify(this.state))
        
      }
      
    
      render() {
        return (
          <BrowserRouter>
                <Route path='/navigation' component={Navigation} />
            <div className='app'>
            {this.props.role === "admin" ? <Navigation/>:(this.props.role === "manager" ? <NavigationManager/>:(this.props.role === "submanager"?<NavigationSubManager/>:null ) )}
              {/* <!-- Navbar goes here --> */}
              
    
              <div className="row">
            
    {/* <Tab></Tab> */}
    
                <div className='col s12 m8 l9  offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
                  {/* <!-- Note that "m8 l9" was added --> */}
                  {/* <!-- Teal page content */}
    
                  <div className="Login white">
         <h1 className="center black-text">Scan Services</h1>
               <br />
         <form onSubmit={this.handleSubmit}>
             
           <FormGroup className="form1" controlId="IPaddress" bsSize="large">
             <controlId className="black-text">IP address</controlId>
          <FormControl
                name= "ip"
                  autoFocus
                  type="text"
                  value={this.state.IPadress}
                  onChange={(e)=>this.handleChange(e, "IPaddress")}
                />
              </FormGroup>
          
          
            
              <Button
               className="btn btn-danger black-text"
                block
                bsSize="small"
               disabled={!this.validateForm()}
                type="submit"
                onSubmit={(e)=>this.handleSubmit(e)}
                
              >
               Scan
              </Button>

              <Button
               className="waves-effect waves-light btn"
                block
                bsSize="small"
              //  disabled={!this.validateForm()}
                type="submit"
                // onSubmit={(e)=>this.handleSubmit(e)}
                href={this.props.role === "admin" ?'/viewscan':(this.props.role  === "manager" ? '/managerviewscan':null ) }
              >
               View Scan Result
              </Button>
             
             
    {/* <h3 className="center black-text"  style={{ borderTop: "solid",paddingTop:"10px"}}>Status</h3> */}
    {/* <br></br> */}
    
   
    
  
            </form>
            
            
          </div>

          


    
          </div>


         
                </div>
              
              </div>
            
           
          </BrowserRouter>
        )}
}
Scanner.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps)(Scanner)

