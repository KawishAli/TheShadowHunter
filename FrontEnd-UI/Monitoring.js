import React, { Component } from 'react';
import './Monitoring.css';
import { BrowserRouter, Route } from 'react-router-dom';
import Monitoring from './Monitoring.js';

import Signup from './Signup.js';
import Dashboard from './Dashboard';
import Navigation from './Navigation'
import PropTypes from 'prop-types'
import {connect} from 'react-redux'
import moment from "moment";
import NavigationManager from './NavigationManager'
import NavigationSubManager from './NavigationSubManager'
import axios from 'axios';


class Monitorings extends Component {
    constructor(props){
        super(props)
        this.state={
            managers:null,
            submanagers: null,
            departments: null,
            services: null
        }



        axios({
            method: 'post',
            url: 'http://localhost:5000/api/users/getdepartment'
            
        })
            .then(response => {
                  this.setState({departments: response.data.departments})
                    
            })
            .catch(err => alert(err + 'Could not get departments'));

            axios({
              method: 'post',
              url: 'http://localhost:5000/api/users/getservices',//'http://115.186.176.139:5000/api/attacksessions/startattacksession',
              
          })
    
        
        .then(response => {
              this.setState({services: response.data.services})
                
        })
        .catch(err => alert(err + 'Could not get services'));


    }

   rowDiv(i){

    if ((i)%4 === 0){
    
      return(
         <div className='row'>
           <div className="col s12 m12 l12">
             </div>
             </div>
         )
     
       }
      else{
return(null)
      }

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
    let cards =[]
    let elements =[]
    let vmcards=[]
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

    {/* <div className="row" > */}
         {
          
              
            this.state.departments ? this.state.departments.map((fields, i)=>
            {
             elements.push(
               
                <div key={fields.IPaddress} className="col s12 m4 l4">
                              <div className='card text-black o-hidden white h-100' >
                              <i class="large material-icons center">desktop_windows</i>
                                    <div className='card-body'>
                              <h2 className="center">Department</h2>
                              <hr></hr>
                              <h4>IP Address: {fields.IPaddress}</h4>
                              <hr></hr>
                              <h6>Account used: {fields.account}</h6>
                              <hr></hr>
                              <h6>Account password: {fields.password}</h6>
                              <hr></hr>
                              <h6>{moment (new Date(fields.date)).format('DD/MM/YYYY , hh:mm:ss:A')}</h6>
                              <hr></hr>
                              <button class="btn btn-danger"value={JSON.stringify(fields)}  onClick={e=>this.deleteService(e)}>
                   Delete
                  </button>

                </div>
                </div>           
                              </div>)
                              
                  
                  if ((i+1)%3 === 0){
    
                   cards.push( <div className ="row">
                   {elements}
                 </div>)
                   elements=[]
                   
                   
                     }
                     if (i+1 === this.state.departments.length){
                      if(elements.length >0 ){
                        console.log(elements)
                          cards.push( <div className ="row">
                          {elements}
                        </div>)
                          elements=[]
                     }
            }
          }
           ) 
          : null
        }
        {/* dalta pori ba copy ke */}

        

        {
           
              
          this.state.services ? this.state.services.map((fields, i)=>
          {
           elements.push(
             
              <div key={fields.IPaddress} className="col s12 m4 l4">
                <hr></hr>
                            <div className='card text-black o-hidden white h-100' >
                            <i class="large material-icons center">desktop_mac</i>
                                  <div className='card-body'>
                            <h2 className="center">VM</h2>
                            <hr></hr>
                            <h4>IP Address: {fields.IPaddress}</h4>
                            
                            <hr></hr>
                            <h6>Account used: {fields.account}</h6>
                            <hr></hr>
                            <h6>Account password: {fields.password}</h6>
                            <hr></hr>
                            <h6>VM up: {fields.service}</h6>
                            <hr></hr>
                            <h6>{moment (new Date(fields.date)).format('DD/MM/YYYY , hh:mm:ss:A')}</h6>
                            <hr></hr>
                            {/* <div className="led-box" style={{marginLeft:'37%'}}>
                        <div className="led-green" > </div>
    
                                
                                
                        <div className="led-green" > </div>
    
                                
                              
                        <div className="led-green" > </div>
    
                        </div>
                                 <hr></hr> */}
                            <button class="btn btn-danger"value={JSON.stringify(fields)}  onClick={e=>this.deleteService(e)}>
                 Delete
                </button>

              </div>
              </div>           
                            </div>)
                
                if ((i+1)%3 === 0){
  
                 vmcards.push( <div className ="row">
                 {elements}
               </div>)
                 elements=[]
                 
                 
                   }
                   if (i+1 === this.state.services.length){
                    if(elements.length >0 ){
                      console.log(elements)
                        vmcards.push( <div className ="row">
                        {elements}
                      </div>)
                        elements=[]
                   }
          }
        }
         ) 
        : null
      }




    {  cards }
    {  vmcards }
        </div>

                
              </div>
           
          </div>
      </BrowserRouter>
    );
  }
}

Monitorings.propTypes = {
  isAuthenticated: PropTypes.bool,
};

const mapStateToProps = state => ({
  isAuthenticated: state.auth.isAuthenticated,
  token: state.auth.token,
  role: state.auth.role
})

export default connect(mapStateToProps)(Monitorings)

