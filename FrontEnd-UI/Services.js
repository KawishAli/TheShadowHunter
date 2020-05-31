import React, { Component } from 'react';
import './UserManagement.css';
import LineChart from './LineChart';
import BarChart from './BarChart';
import { BrowserRouter, Route } from 'react-router-dom';
// import Monitoring from './Monitoring.js';
import AddedVM from './AddedVM.js';
import Signup from './Signup.js';
import Dashboard from './Dashboard';
import Monitoring from './Monitoring.js';
import Manageraddrole from './Manageraddrole';
import Updaterole from './Updaterole';
import Deleterole from './Deleterole';
// import dashboard from './dashboard.js';
import Logs from './Logs.js';
import Navigation from './Navigation';
import PropTypes from 'prop-types'
import {connect} from 'react-redux'

import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
import addservices from './Addservices';
class Services extends Component {
  render() {
    return (
      <BrowserRouter>
        <Route path='/navigation' component={Navigation} />
        <Route path='/addservices' component={Services}/>
        <div className='app'>
        {this.props.role === "admin" ? <Navigation/>:(this.props.role === "manager" ? <NavigationManager/>:(this.props.role === "submanager"?<NavigationSubManager/>:null ) )}
          {/* <!-- Navbar goes here --> */}
         

          <div className='row'>
           

            <div className='col s12 m8 l9 offset-l2 main' style={{marginLeft:'18%', marginRight:"1%"}}>
              {/* <!-- Note that "m8 l9" was added --> */}
              {/* <!-- Teal page content */}

              <h3>Service Management</h3>

              <div class='row'>
              <div className="col s12 m4 l4">
              <div className='card text-white o-hidden green h-100'>
                    <div className='card-body'>
           <h4> Add Service</h4>
         <a  href={this.props.role === "admin" ?'/addservices':(this.props.role  === "manager" ? '/manageraddservices':null ) } class="btn waves-effect white waves-light" type="submit" name="action">Add
        <i class="material-icons right">send</i>
        </a>
              </div>
              </div>
              </div>

              <div className="col s12 m4 l4">
              <div className='card text-white o-hidden light-blue h-100'>
                    <div className='card-body'>
              <h4> Update Service</h4>
              <a href="/updaterole" class="btn waves-effect white waves-light" type="submit" name="action">Update
    <i class="material-icons right">send</i>
  </a>
</div>
</div>
              </div>
              <div className="col s12 m4 l4">
              <div className='card text-white o-hidden yellow h-100'>
                    <div className='card-body'>
              <h4> Delete Service</h4>
              <a href="/deleterole" class="btn waves-effect white waves-light" type="submit" name="action">Delete
    <i class="material-icons right">send</i>
  </a>
  </div>
  </div>
              </div>
              
              </div>
            </div>
          </div>
        </div>
      </BrowserRouter>
    );
  }
}
Services.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps)(Services)


