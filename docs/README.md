# Introduction
   
# Integrity Enforcer (IE)
  Integrity Enforcer is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

  Integrity Enforcer's capabilities are 

  - Allow to deploy authorized application pakcages only
  - Allow to use signed deployment params only
  - Zero-drift in resource configuration unless whitelisted
  - Perform all integrity verification on cluster (admission controller, not in client side)
  - Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

# Quick Start
  see documentation [here](../README_QUICK_START.md)
 
# Integrity Enforcement with IE
  If you would like to check how IE's integrity enforcement works, see documentaion [here](../README_INTEGRITY_ENFORCEMENT.md)
  
