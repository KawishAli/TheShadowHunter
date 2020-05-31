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

import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
// import dashboard from './dashboard.js';
class Logs extends Component {
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
                      <th>Time</th>
                      <th>Source Type</th>
                      <th>IP</th>
                      <th>Ports</th>
                      <th>Events</th>
                    </tr>
                  </thead>

                  <tbody>
                    <tr>
                      <td>15-8-2019 1:00 PM</td>
                      <td>Sysmon</td>
                      <td>192.168.1.0</td>
                      <td>22</td>
                      <td>ProcessId, EventId</td>
                    </tr>
                    <tr>
                      <td>15-8-2019 1:00 PM</td>
                      <td>Sysmon</td>
                      <td>192.168.1.0</td>
                      <td>22</td>
                      <td>ProcessId, EventId</td>
                    </tr>
                    <tr>
                      <td>15-8-2019 1:00 PM</td>
                      <td>Sysmon</td>
                      <td>192.168.1.0</td>
                      <td>22</td>
                      <td>ProcessId, EventId</td>
                    </tr>
                    <tr>
                      <td>15-8-2019 1:00 PM</td>
                      <td>Sysmon</td>
                      <td>192.168.1.0</td>
                      <td>22</td>
                      <td>ProcessId, EventId</td>
                    </tr>
                  </tbody>
                </table>
                <button
                  class='button1'
                  class='btn waves-effect waves-light'
                  type='submit'
                  name='action'
                >
                  Download
                  <i class='material-icons right'>arrow_downward</i>
                </button>
              </div>
            </div>
          </div>
        </div>
      </BrowserRouter>
    );
  }
}
Logs.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps)(Logs)

