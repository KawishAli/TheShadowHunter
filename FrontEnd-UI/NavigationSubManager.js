import React, { Component } from 'react';
import { BrowserRouter, Route } from 'react-router-dom';

import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import AddedVM from './AddedVM.js';
// import Signup from './Signup.js';
import Dashboard from './Dashboard';
import Monitoring from './Monitoring.js';
import Updaterole from './Updaterole';
import Deleterole from './Deleterole';
import Roles from './Roles'
import Department from './Department';
import Logs from './Logs.js';
import Services from './Services';
import Manageraddrole from './Manageraddrole'
import Scanner from './Scanner';
import { logout } from '../actions/authAction'

import './Navigation.css'


class NavigationSubManager extends Component {
  render() {
    return (
      <BrowserRouter>
        {/* <Route path='./managerdashboard' component={Dashboard} />
        <Route path='./managerlogs' component={Logs} />
        <Route path='./managermonitoring' component={Monitoring} />
        {/* <Route path='./signup' component={Signup} /> */}
        {/* <Route path='./managerconfiguration' component={Configuration} />
        <Route path='./managerdepartment' component={Department}/>
        <Route path='./managerservices' component={Services}/>
        <Route path='./managerscanner' component={Scanner}/> */} */}
        <div className='app'>
          {/* <!-- Navbar goes here --> */}
          <div className='row'>
            <div className='col s12 m12 l12'>
              <nav>
                <div className='nav-wrapper '>
                  <a href='/submanagerdashboard' className='brand-logo'>
                   Shadow Hunter
                  </a>
                  <ul className='right hide-on-med-and-down'>
                    <li>
                      <a href='sass.html'>
                        <i className='material-icons'>search</i>
                      </a>
                    </li>
                    <li>
                      <a href='badges.html'>
                        <i className='material-icons'> notifications </i>
                      </a>
                    </li>
                    <li>
                      <a href='collapsible.html'>
                        <i className='material-icons'>mail</i>
                      </a>
                    </li>
                    <li>
                      <a href='/submanagerlogin'>
                        
                        <i className='material-icons' onClick={this.props.logout}>account_circle</i>
                      </a>
                    </li>
                  </ul>
                </div>
              </nav>
            </div>
          </div>

          <div className='row'>
            <div className='col s12 m3 l2 side-bar'>
              {/* <!-- Note that "m4 l3" was added --> */}
              {/* <!-- Grey navigation panel */}

              <ul id='slide-out' className='sidebar'>
                <li>
                  <a href='/submanagerdashboard' className='nav-link  mainNav'>
                    Home
                  </a>
                </li>
                <li>
                  <a href='/submanagerlogs' className='nav-link  mainNav'>
                    Logs
                  </a>
                </li>
               
                <li>
                  <a href='/submanageraddedvm' className='nav-link  mainNav'>
                     AddedVM
                  </a>
                </li>
                <li>
                  <a href='/submanagermonitoring' className='nav-link  mainNav'>
                    Monitoring
                  </a>
                </li>
                
              </ul>
              {/* <a href="#" data-target="slide-out" className="sidenav-trigger"><i class="material-icons">menu</i></a>    */}
            </div>
            </div>
            </div>
        </BrowserRouter>
        );
        }
}

NavigationSubManager.propTypes = {
  logout: PropTypes.func.isRequired
}

const mapStateToProps = state => ({
  auth: state.auth,
  page: state.page
})
export default connect(mapStateToProps, {logout})(NavigationSubManager);