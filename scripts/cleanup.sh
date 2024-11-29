#!/bin/bash
echo "Deleting k3d cluster."
k3d cluster delete my-cluster
echo "Cleaning up Virtual Machine."
vagrant halt
echo "Done cleaning up."
