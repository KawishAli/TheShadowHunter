import React, { Component } from 'react';
import './Logs.css';
import { BrowserRouter, Route } from 'react-router-dom';
import Monitoring from './Monitoring.js';
import AddedVM from './AddedVM.js';
import Signup from './Signup.js';
import Dashboard from './Dashboard';
import Navigation from './Navigation'
import PropTypes from 'prop-types'
import {connect} from 'react-redux'
import moment from "moment";
import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
import axios from 'axios';
// import dashboard from './dashboard.js';
class ViewManager extends Component {
    constructor(props){
        super(props)
        this.state={
            managers:null,
            submanagers: null
        }

        axios({
            method: 'post',
            url: 'http://localhost:5000/api/users/getmanagers',//'http://115.186.176.139:5000/api/attacksessions/startattacksession',
            
        })
            .then(response => {
                  this.setState({managers: response.data.managers})
                    
            })
            .catch(err => alert(err + 'Could not get managers'));
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
                      <th>Username</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Date</th>
                    </tr>
                  </thead>

                  <tbody>
        {
            this.state.managers ? this.state.managers.map((fields)=>
            {
                return(

                    <tr>
                    <td>{fields.username}</td>
                    <td>{fields.email}</td>
                    <td>Manager</td>
                    <td>{moment (new Date(fields.date)).format('DD/MM/YYYY , hh:mm:ss:A')}</td>
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

ViewManager.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps)(ViewManager)

