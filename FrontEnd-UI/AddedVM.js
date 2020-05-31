import React, { Component } from 'react';
import './Logs.css';
import { BrowserRouter, Route } from 'react-router-dom';
import Monitoring from './Monitoring.js';

import Signup from './Signup.js';
import Dashboard from './Dashboard';
import Navigation from './Navigation'
import PropTypes from 'prop-types'
import {connect} from 'react-redux'

import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
import axios from 'axios';
import moment from "moment";
// import dashboard from './dashboard.js';
class AddedVM extends Component {
    constructor(props){
        super(props)
        this.state={
            managers:null,
            submanagers: null,
            services: null
        }

        axios({
            method: 'post',
            url: 'http://localhost:5000/api/users/getservices',//'http://115.186.176.139:5000/api/attacksessions/startattacksession',
            
        })
            .then(response => {
                  this.setState({services: response.data.services})
                    
            })
            .catch(err => alert(err + 'Could not get services'));
    }

deleteService(e){
console.log(e.target.value)

axios(
  {
  method: "post",
  url:"http://192.168.1.110:8080/execute-VM",
  data: {"ip_address":(e.target.value)}
}
).then(res=>{
  console.log(res.e.target.value);
  //  updateStatus(res.data);

}).catch(err=>{console.log(err)})
console.log(JSON.stringify(e.target.value))




}
    
  render() {
    return (
      <BrowserRouter>
          <Route path='/navigation' component={Navigation} />
        <div className='app'>
        {this.props.role === "admin" ? <Navigation/>:(this.props.role === "manager" ? <NavigationManager/>:(this.props.role === "submanager"?<NavigationSubManager/>:null ) )}
          {/* <!-- Navbar goes here --> */}
         

          <div className='row'>
    

            <div className='col s12 m8 l9 offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
              {/* <!-- Note that "m8 l9" was added --> */}
              {/* <!-- Teal page content */}

              <div className='row'>
                <table
                  class='striped'
                  class='highlight'
                  class='responsive-table'
                  class='centered'
                >
                  <thead>
                    <tr>
                      <th>IPaddress</th>
                      <th>Account</th>
                      <th>Password</th>
                      <th>service</th>
                      <th>Date</th>
                      <th>Delete</th>
                    </tr>
                  </thead>

                  <tbody>
        {
            this.state.services ? this.state.services.map((fields)=>
            {
                return(

                    <tr>
                    <td>{fields.IPaddress}</td>
                    <td>{fields.account}</td>
                    <td>{fields.password}</td>
                    <td>{fields.service}</td>
                    <td>{moment (new Date(fields.date)).format('DD/MM/YYYY , hh:mm:ss:A')}</td>
                    <td><button className="btn btn-danger" value={JSON.stringify(fields)}  onClick={e=>this.deleteService(e)}> Delete</button></td>
                  </tr>
                )
            }
            ) : null
        }

                  </tbody>
                </table>
                
              </div>
            </div>
          </div>
        </div>
      </BrowserRouter>
    );
  }
}

AddedVM.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps)(AddedVM)

