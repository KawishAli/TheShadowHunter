import React, { Component } from "react";
import { Button, FormGroup, FormControl, controlId } from "react-bootstrap";
// import "./Login.css";

class Updaterole extends Component {
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
      <div className="Login">
        <h1 className="center white-text">Update role</h1>
        <br />
        <form onSubmit={this.handleSubmit}>
          <FormGroup controlId="email" bsSize="large">
            <controlId className="white-text">username</controlId>
            <FormControl
              autoFocus
              type="text"
              value={this.state.username}
              onChange={this.handleChange}
            />
          </FormGroup>
          <FormGroup controlId="email" bsSize="large">
            <controlId className="white-text">Email</controlId>
            <FormControl
            className="white-text"
              value={this.state.email}
              onChange={this.handleChange}
              type="email"
            />
          </FormGroup>
          <FormGroup controlId="email" bsSize="large">
            <controlId className="white-text">Role</controlId>
            <FormControl
            className="white-text"
              value={this.state.role}
              onChange={this.handleChange}
              type="text"
            />
          </FormGroup>
          <Button
           className="btn btn-danger white-text"
            block
            bsSize="small"
            disabled={!this.validateForm()}
            type="submit"
            
          >
            Update
          </Button>
        </form>
      </div>
    );
  }
}
export default Updaterole;
