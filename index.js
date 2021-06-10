import bcrypt from "bcrypt"

const plainPW = "Diego1234"
const plainPW2 = "diego1234"

console.time("bcrypt")
const hash = bcrypt.hashSync(plainPW, 10)
const hash2 = bcrypt.hashSync(plainPW2, 10)
console.log(hash)
console.log(hash2)
console.timeEnd("bcrypt")

const isEqual = bcrypt.compareSync(plainPW2, hash)

console.log(isEqual)
