const express = require('express');
const router = express.Router();
const db = require('../../helpers/db');
const authorize = require('../../middleware/authorize');
const Role = require('../../helpers/role');

router.post('/', authorize(), create);
router.get('/', authorize(Role.Admin), getAll);
router.get('/:id', authorize(), getById);
router.get('/employee/:employeeid', authorize(), getByEmployeeId);
router.put('/:id', authorize(Role.Admin), update);
router.delete('/:id', authorize(Role.Admin), _delete);

async function create(req, res, next) {
  try {
    const request = await db.Request.create({
      ...req.body,
      employeeid: req.user.employeeid
    }, {
      include: [{ model: db.RequestItem }]
    });
    res.status(201).json(request);
  } catch (err) { next(err); }
}

async function getAll(req, res, next) {
  try {
    const requests = await db.Request.findAll({
      include: [{ model: db.RequestItem }, { model: db.Employee }]
    });
    res.json(requests);
  } catch (err) { next(err); }
}

async function getById(req, res, next) {
  try {
    const request = await db.Request.findByPk(req.params.id, {
      include: [{ model: db.RequestItem }, { model: db.Employee }]
    });

    if (!request) throw new Error('Request not found');
    if (req.user.role !== Role.Admin && request.employeeid !== req.user.employeeid) {
      throw new Error('Unauthorized');
    }

    res.json(request);
  } catch (err) { next(err); }
}

async function getByEmployeeId(req, res, next) {
  try {
    const requests = await db.Request.findAll({
      where: { employeeid: req.params.employeeid },
      include: [{ model: db.RequestItem }]
    });
    res.json(requests);
  } catch (err) { next(err); }
}

async function update(req, res, next) {
  try {
    const request = await db.Request.findByPk(req.params.id);
    if (!request) throw new Error('Request not found');

    await request.update(req.body);

    if (req.body.items) {
      await db.RequestItem.destroy({ where: { requestid: request.id } });
      await db.RequestItem.bulkCreate(req.body.items.map(item => ({
        ...item,
        requestid: request.id
      })));
    }

    res.json(request);
  } catch (err) { next(err); }
}

async function _delete(req, res, next) {
  try {
    const request = await db.Request.findByPk(req.params.id);
    if (!request) throw new Error('Request not found');

    await request.destroy();
    res.json({ message: 'Request deleted' });
  } catch (err) { next(err); }
}

module.exports = router;
