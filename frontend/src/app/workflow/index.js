const express = require('express');
const router = express.Router();
const db = require('../../helpers/db');
const authorize = require('../../middleware/authorize');
const Role = require('../../helpers/role');

router.post('/', authorize(Role.Admin), create);
router.get('/employee/:employeeId', authorize(), getByEmployeeId);
router.put('/:id/status', authorize(Role.Admin), updateStatus);
router.post('/onboarding', authorize(Role.Admin), onboarding);

// Create workflow
async function create(req, res, next) {
  try {
    const workflow = await db.Workflow.create(req.body);
    res.status(201).json(workflow);
  } catch (err) {
    next(err);
  }
}

// Get workflows by employee ID
async function getByEmployeeId(req, res, next) {
  try {
    const workflows = await db.Workflow.findAll({
      where: { employeeId: req.params.employeeId }
    });
    res.json(workflows);
  } catch (err) {
    next(err);
  }
}

// Update workflow status
async function updateStatus(req, res, next) {
  try {
    const workflow = await db.Workflow.findByPk(req.params.id);
    if (!workflow) throw new Error('Workflow not found');

    await workflow.update({ status: req.body.status });
    res.json(workflow);
  } catch (err) {
    next(err);
  }
}

// Onboarding workflow
async function onboarding(req, res, next) {
  try {
    const workflow = await db.Workflow.create({
      employeeId: req.body.employeeId,
      type: 'Onboarding',
      details: req.body.details,
      status: 'Pending'
    });
    res.status(201).json(workflow);
  } catch (err) {
    next(err);
  }
}

module.exports = router;
