const express = require('express');
const router = express.Router();
const db = require('../helpers/db');
const authorize = require('../middleware/authorize');
const Role = require('../helpers/role');

router.post('/', authorize(Role.Admin), create);
router.get('/', authorize(), getAll);
router.get('/:id', authorize(), getById);
router.put('/:id', authorize(Role.Admin), update);
router.delete('/:id', authorize(Role.Admin), _delete);
router.post('/:id/transfer', authorize(Role.Admin), transfer);

async function create(req, res, next) {
  try {
    const employee = await db.Employee.create(req.body);
    res.status(201).json(employee);
  } catch (err) {
    next(err);
  }
}

async function getAll(req, res, next) {
  try {
    const employees = await db.Employee.findAll({
      include: [
        { model: db.User },
        { model: db.Department }
      ]
    });
    res.json(employees);
  } catch (err) {
    next(err);
  }
}

async function getById(req, res, next) {
  try {
    const employee = await db.Employee.findByPk(req.params.id, {
      include: [
        { model: db.User },
        { model: db.Department }
      ]
    });
    if (!employee) throw new Error('Employee not found');
    res.json(employee);
  } catch (err) {
    next(err);
  }
}

async function update(req, res, next) {
  try {
    const employee = await db.Employee.findByPk(req.params.id);
    if (!employee) throw new Error('Employee not found');
    await employee.update(req.body);
    res.json(employee);
  } catch (err) {
    next(err);
  }
}

async function _delete(req, res, next) {
  try {
    const employee = await db.Employee.findByPk(req.params.id);
    if (!employee) throw new Error('Employee not found');
    await employee.destroy();
    res.json({ message: 'Employee deleted' });
  } catch (err) {
    next(err);
  }
}

async function transfer(req, res, next) {
  try {
    const employee = await db.Employee.findByPk(req.params.id);
    if (!employee) throw new Error('Employee not found');
    await employee.update({ departmentId: req.body.departmentId });
    await db.Workflow.create({
      employeeId: employee.id,
      type: 'Transfer',
      details: { newDepartmentId: req.body.departmentId }
    });
    res.json({ message: 'Employee transferred' });
  } catch (err) {
    next(err);
  }
}

module.exports = router;
