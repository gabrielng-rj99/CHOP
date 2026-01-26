/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package repository

import "strings"

// isValidCPFOrCNPJ validates CPF or CNPJ format and check digits
// This is an internal function used by validation helpers
func isValidCPFOrCNPJ(id string) bool {
	id = strings.ReplaceAll(id, ".", "")
	id = strings.ReplaceAll(id, "-", "")
	id = strings.ReplaceAll(id, "/", "")
	id = strings.TrimSpace(id)

	if len(id) == 11 {
		return isValidCPF(id)
	}
	if len(id) == 14 {
		return isValidCNPJ(id)
	}
	return false
}

// isValidCPF checks CPF format and digits
// CPF must be exactly 11 numeric digits with valid check digits
func isValidCPF(cpf string) bool {
	if len(cpf) != 11 {
		return false
	}
	// Reject all digits equal
	for _, d := range []string{
		"00000000000", "11111111111", "22222222222", "33333333333",
		"44444444444", "55555555555", "66666666666", "77777777777",
		"88888888888", "99999999999",
	} {
		if cpf == d {
			return false
		}
	}
	// Validate check digits
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(cpf[i]-'0') * (10 - i)
	}
	d1 := (sum * 10) % 11
	if d1 == 10 {
		d1 = 0
	}
	if d1 != int(cpf[9]-'0') {
		return false
	}
	sum = 0
	for i := 0; i < 10; i++ {
		sum += int(cpf[i]-'0') * (11 - i)
	}
	d2 := (sum * 10) % 11
	if d2 == 10 {
		d2 = 0
	}
	return d2 == int(cpf[10]-'0')
}

// isValidCNPJ checks CNPJ format and digits
// CNPJ must be exactly 14 numeric digits with valid check digits
func isValidCNPJ(cnpj string) bool {
	if len(cnpj) != 14 {
		return false
	}
	// Reject all digits equal
	for _, d := range []string{
		"00000000000000", "11111111111111", "22222222222222", "33333333333333",
		"44444444444444", "55555555555555", "66666666666666", "77777777777777",
		"88888888888888", "99999999999999",
	} {
		if cnpj == d {
			return false
		}
	}
	var calc = func(cnpj string, length int) int {
		sum := 0
		weight := []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
		if length == 13 {
			weight = append([]int{6}, weight...)
		}
		for i := 0; i < length; i++ {
			sum += int(cnpj[i]-'0') * weight[i]
		}
		d := sum % 11
		if d < 2 {
			return 0
		}
		return 11 - d
	}
	d1 := calc(cnpj, 12)
	d2 := calc(cnpj, 13)
	return d1 == int(cnpj[12]-'0') && d2 == int(cnpj[13]-'0')
}
