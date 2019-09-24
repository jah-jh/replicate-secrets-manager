plan:
	terraform plan -var $(S_REG) -var $(T_REG)
apply:
	terraform apply -var $(S_REG) -var $(T_REG)
destroy:
	terraform destroy -var $(S_REG) -var $(T_REG)

